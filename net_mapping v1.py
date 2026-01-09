#!/usr/bin/env python3
"""
Crawler with:
- Domain Viewer: multi-level expandable tree (collapsed by default), manual Refresh only
- Queue Viewer tab: top slider (10-250), Auto Refresh ON/OFF, selectable non-editable XY scroll text,
  capped at 250 lines, auto-refresh when queue item is solved (visited).
- Queue can be undocked into its own window for side-by-side viewing.
- Yellow highlight for user-search links (shared across viewers)
- Other previous fixes retained (requests.Session, set.discard, slider label update)
"""
import threading
import time
import json
import webbrowser
from collections import deque
from queue import Queue, Empty
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# ---------- Worker ----------
def crawler_worker(seed_url, delay_getter, ui_queue, stop_event, pause_event, state):
    headers = {"User-Agent": "Optimized-Web-Crawler/1.0 (+https://example.local)"}
    session = requests.Session()
    while not stop_event.is_set():
        # pause responsive
        while pause_event.is_set() and not stop_event.is_set():
            time.sleep(0.05)

        with state["lock"]:
            if not state["pending_queue"]:
                ui_queue.put(("info", "Crawl complete (pending empty)."))
                break
            url = state["pending_queue"].popleft()
            state["pending_set"].discard(url)
            # skip already visited
            if url in state["visited"]:
                continue
            state["visited"].add(url)
            visited_count = len(state["visited"])

        ui_queue.put(("visited", url, visited_count))

        # GET page
        try:
            resp = session.get(url, headers=headers, timeout=8)
            resp.raise_for_status()
        except Exception as e:
            ui_queue.put(("error", f"{url} -> {repr(e)}"))
            # delay
            d = delay_getter()
            slept = 0.0
            step = 0.02
            while slept < d and not stop_event.is_set():
                if pause_event.is_set():
                    break
                time.sleep(min(step, d - slept))
                slept += step
            continue

        content_type = (resp.headers.get("Content-Type") or "").lower()
        is_html = "text/html" in content_type

        if not is_html:
            # mark non-html and log
            with state["lock"]:
                state["non_html_set"].add(url)
            ui_queue.put(("note_nonhtml", url, content_type))
            d = delay_getter()
            slept = 0.0
            step = 0.02
            while slept < d and not stop_event.is_set():
                if pause_event.is_set():
                    break
                time.sleep(min(step, d - slept))
                slept += step
            continue

        # parse links
        last_found = None
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            found = []
            for tag in soup.find_all("a", href=True):
                raw = tag["href"]
                joined = urljoin(url, raw)
                joined, _ = urldefrag(joined)
                p = urlparse(joined)
                if p.scheme not in ("http", "https"):
                    continue
                found.append(joined)
            with state["lock"]:
                for link in found:
                    if link not in state["visited"] and link not in state["pending_set"]:
                        state["pending_set"].add(link)
                        state["pending_queue"].append(link)
                        dk = p_join_domain(link)
                        state["domain_map"].setdefault(dk, set()).add(link)
                        last_found = link
                discovered_total = len(state["visited"]) + len(state["pending_set"])
        except Exception as e:
            ui_queue.put(("error", f"parse error {url} -> {repr(e)}"))
            with state["lock"]:
                discovered_total = len(state["visited"]) + len(state["pending_set"])

        if last_found:
            ui_queue.put(("discovered", last_found, discovered_total))
        else:
            ui_queue.put(("counts", discovered_total, visited_count))

        # delay
        d = delay_getter()
        slept = 0.0
        step = 0.02
        while slept < d and not stop_event.is_set():
            if pause_event.is_set():
                break
            time.sleep(min(step, d - slept))
            slept += step

    with state["lock"]:
        final_visited = len(state["visited"])
    ui_queue.put(("finished", final_visited))

def p_join_domain(url):
    parsed = urlparse(url)
    scheme = parsed.scheme
    netloc = parsed.netloc.lower()
    return f"{scheme}://{netloc}"

# ---------- Modal forced choice ----------
class ForceChoiceDialog(tk.Toplevel):
    def __init__(self, parent, title, message):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.title(title)
        self.resizable(False, False)
        self.result = None

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text=message, wraplength=420).pack(pady=(0,12))
        btnfrm = ttk.Frame(frm)
        btnfrm.pack()
        def yes(): self.result="yes"; self.destroy()
        def no(): self.result="no"; self.destroy()
        def cancel(): self.result="cancel"; self.destroy()
        ttk.Button(btnfrm, text="Yes", command=yes).pack(side=tk.LEFT, padx=6)
        ttk.Button(btnfrm, text="No", command=no).pack(side=tk.LEFT, padx=6)
        ttk.Button(btnfrm, text="Cancel", command=cancel).pack(side=tk.LEFT, padx=6)
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width()//2) - (self.winfo_width()//2)
        y = parent.winfo_rooty() + (parent.winfo_height()//2) - (self.winfo_height()//2)
        self.geometry(f"+{x}+{y}")

# ---------- App ----------
class CrawlerApp:
    def __init__(self, root):
        self.root = root
        root.title("Crawler — full")
        # top controls
        top = ttk.Frame(root, padding=(8,6)); top.pack(fill=tk.X)
        ttk.Label(top, text="Seed URL:").grid(row=0,column=0,sticky=tk.W)
        self.url_var = tk.StringVar()
        self.entry_url = ttk.Entry(top, textvariable=self.url_var, width=60)
        self.entry_url.grid(row=0,column=1,columnspan=3,padx=(6,6),sticky=tk.W)

        # Delay
        ttk.Label(top, text="Delay (ms):").grid(row=1,column=0,sticky=tk.W,pady=(6,0))
        self.delay_ms = tk.IntVar(value=50)
        self.delay_slider = ttk.Scale(top, from_=1, to=5000, orient=tk.HORIZONTAL, command=self._on_slider_move, length=300)
        self.delay_slider.set(self.delay_ms.get()); self.delay_slider.grid(row=1,column=1,sticky=tk.W,pady=(6,0))
        self.delay_label = ttk.Label(top, text=f"{self.delay_ms.get()} ms"); self.delay_label.grid(row=1,column=2,sticky=tk.W,padx=(6,0),pady=(6,0))

        # Buttons
        self.btn_start = ttk.Button(top, text="Start Crawl", command=self.start_crawl); self.btn_start.grid(row=0,column=4,padx=(8,0))
        self.btn_pause = ttk.Button(top, text="Pause", command=self.toggle_pause, state=tk.DISABLED); self.btn_pause.grid(row=0,column=5,padx=(6,0))
        self.btn_stop = ttk.Button(top, text="Stop", command=self.stop_crawl, state=tk.DISABLED); self.btn_stop.grid(row=0,column=6,padx=(6,0))
        self.btn_import = ttk.Button(top, text="Import JSON", command=self.import_json); self.btn_import.grid(row=1,column=4,padx=(8,0))
        self.btn_export = ttk.Button(top, text="Export JSON", command=self.export_json); self.btn_export.grid(row=1,column=5,padx=(6,0))

        # Notebook
        self.notebook = ttk.Notebook(root); self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(6,0))

        # Tab: Log (with its own search/filter)
        self.tab_log = ttk.Frame(self.notebook)
        log_top = ttk.Frame(self.tab_log); log_top.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(log_top, text="Search:").pack(side=tk.LEFT)
        self.log_search_var = tk.StringVar()
        self.log_search_var.trace_add("write", lambda *a: self._apply_log_filter())
        self.log_search = ttk.Entry(log_top, textvariable=self.log_search_var, width=30); self.log_search.pack(side=tk.LEFT, padx=(6,4))
        ttk.Label(log_top, text="Filter:").pack(side=tk.LEFT, padx=(8,0))
        self.log_filter_var = tk.StringVar(value="All")
        self.log_filter = ttk.Combobox(log_top, textvariable=self.log_filter_var, values=["All","HTML only","Non-HTML only"], width=12, state="readonly")
        self.log_filter.pack(side=tk.LEFT, padx=(6,4))
        self.log_filter.bind("<<ComboboxSelected>>", lambda e: self._apply_log_filter())

        # Log text (non-editable but selectable) with horizontal scroll
        tb_frame = ttk.Frame(self.tab_log); tb_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
        self.text_box = scrolledtext.ScrolledText(tb_frame, width=110, height=30, wrap=tk.NONE)  # horizontal scroll enabled via wrap=NONE
        # add horizontal scrollbar
        hsb = ttk.Scrollbar(tb_frame, orient="horizontal", command=self.text_box.xview); hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.text_box.configure(xscrollcommand=hsb.set)
        self.text_box.pack(fill=tk.BOTH, expand=True)
        # tags
        self.text_box.tag_config("nonhtml", foreground="red")
        self.text_box.tag_config("usersearch", background="yellow")
        # disable editing by user; we will enable when writing then disable
        self.text_box.config(state=tk.DISABLED)

        self.notebook.add(self.tab_log, text="Log")

        # Tab: Domain Viewer (with its own search/filter)
        self.tab_domain = ttk.Frame(self.notebook)
        domain_top = ttk.Frame(self.tab_domain); domain_top.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(domain_top, text="Search:").pack(side=tk.LEFT)
        self.dom_search_var = tk.StringVar()
        self.dom_search_var.trace_add("write", lambda *a: None)  # we respect manual refresh only
        self.dom_search = ttk.Entry(domain_top, textvariable=self.dom_search_var, width=30); self.dom_search.pack(side=tk.LEFT, padx=(6,4))
        ttk.Label(domain_top, text="Filter:").pack(side=tk.LEFT, padx=(8,0))
        self.dom_filter_var = tk.StringVar(value="All")
        self.dom_filter = ttk.Combobox(domain_top, textvariable=self.dom_filter_var, values=["All","HTML only","Non-HTML only"], width=12, state="readonly")
        self.dom_filter.pack(side=tk.LEFT, padx=(6,4))
        self.dom_filter.bind("<<ComboboxSelected>>", lambda e: None)  # manual refresh only
        self.btn_domain_refresh = ttk.Button(domain_top, text="Refresh", command=self.refresh_domain_view); self.btn_domain_refresh.pack(side=tk.LEFT, padx=(8,0))
        ttk.Label(domain_top, text="(starts collapsed, alphabetical)").pack(side=tk.LEFT, padx=(8,0))

        # Treeview with horizontal scroll
        tree_frame = ttk.Frame(self.tab_domain); tree_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
        self.domain_tree = ttk.Treeview(tree_frame, show="tree")
        self.domain_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.domain_tree.yview); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb2 = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.domain_tree.xview); hsb2.pack(side=tk.BOTTOM, fill=tk.X)
        self.domain_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb2.set)
        # right-click menu
        self.domain_tree.bind("<Button-3>", self.on_domain_right_click)
        self.domain_tree.bind("<Control-Button-1>", self.on_domain_right_click)
        # bind open event to populate children on demand
        self.domain_tree.bind("<<TreeviewOpen>>", self._on_tree_open)

        self.notebook.add(self.tab_domain, text="Domain Viewer")

        # Tab: Queue Viewer (NEW)
        self.tab_queue = ttk.Frame(self.notebook)
        q_top = ttk.Frame(self.tab_queue); q_top.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(q_top, text="Show:").pack(side=tk.LEFT)
        self.queue_show_var = tk.IntVar(value=100)
        self.queue_slider = ttk.Scale(q_top, from_=10, to=250, orient=tk.HORIZONTAL, command=self._on_queue_slider_move, length=260)
        self.queue_slider.set(self.queue_show_var.get()); self.queue_slider.pack(side=tk.LEFT, padx=(6,4))
        self.queue_show_label = ttk.Label(q_top, text=f"{self.queue_show_var.get()}"); self.queue_show_label.pack(side=tk.LEFT, padx=(6,8))
        # Auto Refresh toggle
        self.queue_auto_var = tk.BooleanVar(value=True)
        self.queue_auto_check = ttk.Checkbutton(q_top, text="Auto Refresh", variable=self.queue_auto_var)
        self.queue_auto_check.pack(side=tk.LEFT, padx=(0,12))
        # Manual Refresh button (useful when auto is off)
        self.queue_refresh_btn = ttk.Button(q_top, text="Refresh", command=self.refresh_queue_view); self.queue_refresh_btn.pack(side=tk.LEFT, padx=(0,8))
        # Undock button (create separate window)
        self.queue_undock_btn = ttk.Button(q_top, text="Undock", command=self.toggle_queue_undock); self.queue_undock_btn.pack(side=tk.LEFT)

        # queue display area
        queue_frame = ttk.Frame(self.tab_queue); queue_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
        self.queue_text = scrolledtext.ScrolledText(queue_frame, width=110, height=30, wrap=tk.NONE)
        qhsb = ttk.Scrollbar(queue_frame, orient="horizontal", command=self.queue_text.xview); qhsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.queue_text.configure(xscrollcommand=qhsb.set)
        self.queue_text.pack(fill=tk.BOTH, expand=True)
        self.queue_text.tag_config("usersearch", background="yellow")
        self.queue_text.config(state=tk.DISABLED)
        # we'll optionally create an undocked window with its own text widget; keep references
        self.queue_undocked_win = None
        self.queue_undocked_text = None

        self.notebook.add(self.tab_queue, text="Queue Viewer")

        # bottom status
        status_frame = ttk.Frame(root); status_frame.pack(fill=tk.X, padx=8, pady=(0,8))
        self.status_var = tk.StringVar(value="Idle")
        self.visited_var = tk.IntVar(value=0); self.inqueue_var = tk.IntVar(value=0); self.discovered_var = tk.IntVar(value=0)
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        ttk.Label(status_frame, text="  Visited:").pack(side=tk.LEFT, padx=(8,0)); ttk.Label(status_frame, textvariable=self.visited_var).pack(side=tk.LEFT)
        ttk.Label(status_frame, text="  In Queue:").pack(side=tk.LEFT, padx=(8,0)); ttk.Label(status_frame, textvariable=self.inqueue_var).pack(side=tk.LEFT)
        ttk.Label(status_frame, text="  Discovered:").pack(side=tk.LEFT, padx=(8,0)); ttk.Label(status_frame, textvariable=self.discovered_var).pack(side=tk.LEFT)
        self.last_discovered_var = tk.StringVar(value=""); ttk.Label(status_frame, text="  Last discovered:").pack(side=tk.LEFT, padx=(12,0))
        self.last_disc_label = ttk.Label(status_frame, textvariable=self.last_discovered_var, wraplength=600); self.last_disc_label.pack(side=tk.LEFT, padx=(6,0))

        # state
        self.ui_queue = Queue()
        self.stop_event = None; self.pause_event = None; self.worker_thread = None
        self.state = {
            "visited": set(),
            "pending_set": set(),
            "pending_queue": deque(),
            "domain_map": {},  # domain -> set(url)
            "non_html_set": set(),
            "usersearch_set": set(),  # URLs user requested
            "lock": threading.Lock()
        }

        # extra cached domain trees used for on-demand population
        self._domain_tree_data = {}  # domain -> nested dict of path segments -> {"__urls": set(), ...}

        # poll UI
        self.root.after(150, self._poll_ui)

    # ---------- helpers ----------
    def _on_slider_move(self, value):
        try:
            ms = int(float(value))
        except Exception:
            ms = self.delay_ms.get()
        self.delay_ms.set(ms)
        try:
            self.delay_label.config(text=f"{ms} ms")
        except Exception:
            pass

    def _on_queue_slider_move(self, value):
        try:
            n = int(float(value))
        except Exception:
            n = self.queue_show_var.get()
        self.queue_show_var.set(n)
        try:
            self.queue_show_label.config(text=f"{n}")
        except Exception:
            pass
        # update immediately
        self.refresh_queue_view()

    def _get_delay_seconds(self):
        return max(0.001, self.delay_ms.get() / 1000.0)

    # safe append to non-editable text
    def _text_insert(self, text, tags=()):
        self.text_box.config(state=tk.NORMAL)
        if tags:
            self.text_box.insert(tk.END, text + "\n", tags)
        else:
            self.text_box.insert(tk.END, text + "\n")
        self.text_box.see(tk.END)
        self.text_box.config(state=tk.DISABLED)

    # ---------- controls ----------
    def start_crawl(self):
        seed = self.url_var.get().strip()
        if not seed:
            messagebox.showwarning("No URL", "Please enter a seed URL."); return
        p = urlparse(seed)
        if not p.scheme: seed = "http://" + seed
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Already running", "Crawler is already running."); return

        # reset UI/state
        self.text_box.config(state=tk.NORMAL); self.text_box.delete(1.0, tk.END); self.text_box.config(state=tk.DISABLED)
        self.status_var.set("Starting..."); self.visited_var.set(0); self.inqueue_var.set(0); self.discovered_var.set(0); self.last_discovered_var.set("")
        with self.state["lock"]:
            self.state["pending_set"].add(seed); self.state["pending_queue"].append(seed)
            dk = p_join_domain(seed); self.state["domain_map"].setdefault(dk, set()).add(seed)

        self.ui_queue = Queue()
        self.stop_event = threading.Event(); self.pause_event = threading.Event()
        self.worker_thread = threading.Thread(target=crawler_worker, args=(seed, self._get_delay_seconds, self.ui_queue, self.stop_event, self.pause_event, self.state), daemon=True)
        self.worker_thread.start()
        self.btn_start.config(state=tk.DISABLED); self.btn_pause.config(state=tk.NORMAL, text="Pause"); self.btn_stop.config(state=tk.NORMAL)
        self.btn_import.config(state=tk.DISABLED)
        self._text_insert(f"[STARTED] seed: {seed}  delay: {self.delay_ms.get()} ms")
        self.status_var.set("Running")

    def toggle_pause(self):
        if not self.pause_event: return
        if self.pause_event.is_set():
            self.pause_event.clear(); self.btn_pause.config(text="Pause"); self._text_insert("[RESUME] Resuming crawl..."); self.status_var.set("Running")
        else:
            self.pause_event.set(); self.btn_pause.config(text="Resume"); self._text_insert("[PAUSE] Paused."); self.status_var.set("Paused")

    def stop_crawl(self):
        if self.stop_event and not self.stop_event.is_set():
            self.stop_event.set(); self._text_insert("[STOP] Stop requested. Waiting for worker to finish..."); self.status_var.set("Stopping...")
            self.btn_stop.config(state=tk.DISABLED); self.btn_pause.config(state=tk.DISABLED)

    # ---------- export/import ----------
    def export_json(self):
        with self.state["lock"]:
            visited_list = list(self.state["visited"]); pending_list = list(self.state["pending_queue"]); nonhtml_list = list(self.state["non_html_set"]); usersearch_list = list(self.state["usersearch_set"])
        data = {"visited": visited_list, "discovered": pending_list, "non_html": nonhtml_list, "usersearch": usersearch_list}
        fname = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json"),("All files","*.*")], title="Export crawl session as JSON")
        if not fname: return
        try:
            with open(fname,"w",encoding="utf-8") as f: json.dump(data,f,indent=2,ensure_ascii=False)
            self._text_insert(f"[EXPORT] Saved session to: {fname}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to save: {e}")

    def import_json(self):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showwarning("Import not allowed", "Stop crawler before importing a session."); return
        fname = filedialog.askopenfilename(filetypes=[("JSON files","*.json"),("All files","*.*")], title="Import crawl session JSON")
        if not fname: return
        try:
            with open(fname,"r",encoding="utf-8") as f: data = json.load(f)
            visited = set(data.get("visited",[])); discovered = list(data.get("discovered",[])); nonhtml = set(data.get("non_html",[])); usersearch = set(data.get("usersearch",[]))
        except Exception as e:
            messagebox.showerror("Import error", f"Failed to load file: {e}"); return

        domain_map = {}
        for u in list(visited) + discovered:
            dk = p_join_domain(u); domain_map.setdefault(dk,set()).add(u)
        with self.state["lock"]:
            self.state["visited"] = set(visited)
            self.state["pending_set"] = set(discovered)
            self.state["pending_queue"] = deque(discovered)
            self.state["domain_map"] = domain_map
            self.state["non_html_set"] = set(nonhtml)
            self.state["usersearch_set"] = set(usersearch)
            if "lock" not in self.state: self.state["lock"]=threading.Lock()
        self._text_insert(f"[IMPORT] Loaded session from: {fname}")
        self.visited_var.set(len(self.state["visited"])); self.inqueue_var.set(len(self.state["pending_queue"])); self.discovered_var.set(len(self.state["visited"])+len(self.state["pending_set"]))
        self.last_discovered_var.set(discovered[-1] if discovered else "")
        # clear domain cache to ensure rebuilt on next refresh
        self._domain_tree_data.clear()

    # ---------- Domain Viewer rebuild (manual Refresh only) ----------
    def refresh_domain_view(self):
        # Disable refresh button briefly
        self.btn_domain_refresh.config(state=tk.DISABLED)
        def snapshot():
            with self.state["lock"]:
                snap = {dom: sorted(list(urls)) for dom,urls in self.state["domain_map"].items()}
                nonhtml_snapshot = set(self.state["non_html_set"])
                usersearch_snapshot = set(self.state["usersearch_set"])
            # build nested path trees for each domain (used for on-demand expansion)
            dom_trees = {}
            for dom, urls in snap.items():
                dom_trees[dom] = self._path_hierarchy(urls)
            # schedule UI populate (pass snapshots)
            self.root.after(10, lambda: self._populate_domain_tree_incremental(dom_trees, nonhtml_snapshot, usersearch_snapshot))
        threading.Thread(target=snapshot,daemon=True).start()

    def _path_hierarchy(self, urls):
        """
        Build nested dict tree for a domain. Example:
        {
          "__urls": set([...])   # URLs that are root '/'
          "blog": {
              "__urls": set([...]),
              "post-1": {"__urls": set([...])},
          },
          "about": {"__urls": set([...])}
        }
        """
        tree = {}
        for u in urls:
            parsed = urlparse(u)
            path = parsed.path or "/"
            if path == "" or path == "/":
                tree.setdefault("__urls", set()).add(u)
                continue
            # break into segments
            segments = [seg for seg in path.split("/") if seg!='']
            node = tree
            for seg in segments:
                node = node.setdefault(seg, {})
            node.setdefault("__urls", set()).add(u)
        return tree

    def _populate_domain_tree_incremental(self, dom_trees, nonhtml_snapshot, usersearch_snapshot):
        # clear existing tree and cache
        for iid in self.domain_tree.get_children(): self.domain_tree.delete(iid)
        self._domain_tree_data = dom_trees  # store for on-demand expansion
        # Insert top-level domain nodes only (collapsed by default); add a dummy child so they are expandable
        domains = sorted(dom_trees.keys())
        for dom in domains:
            node_id = f"dom::{dom}"
            if not self.domain_tree.exists(node_id):
                self.domain_tree.insert("", "end", iid=node_id, text=dom, open=False)
                # dummy child to make it show the expand arrow
                dummy_id = f"{node_id}::DUMMY"
                if not self.domain_tree.exists(dummy_id):
                    self.domain_tree.insert(node_id, "end", iid=dummy_id, text="(loading...)")
                # attach a domain metadata mapping via 'values' so we can find which domain a node belongs to
                # store no real values in columns (we're using tree view only), but we keep _domain_tree_data keyed by domain
        # configure tags once
        try: self.domain_tree.tag_configure("nonhtml", foreground="red")
        except Exception: pass
        try: self.domain_tree.tag_configure("usersearch", background="yellow")
        except Exception: pass
        self.btn_domain_refresh.config(state=tk.NORMAL)

    def _on_tree_open(self, event):
        # Called when a node is expanded. We'll inspect the node and populate its children on demand.
        iid = self.domain_tree.focus()
        if not iid:
            return
        # If it's a domain root node
        if iid.startswith("dom::"):
            dom = iid[len("dom::"):]
            # if dummy child exists, populate top-level children
            children = self.domain_tree.get_children(iid)
            # if only dummy child, populate
            if len(children) == 1 and children[0].endswith("::DUMMY"):
                # remove dummy and populate
                for ch in children:
                    self.domain_tree.delete(ch)
                # populate top-level nodes for this domain using self._domain_tree_data[dom]
                tree = self._domain_tree_data.get(dom, {})
                # Insert any root '/' urls
                urls_at_root = sorted(tree.get("__urls", []))
                for u in urls_at_root:
                    node_id = f"url::{u}"
                    if not self.domain_tree.exists(node_id):
                        display = "/"
                        tags = ()
                        if u in self.state["non_html_set"]: tags = tuple(list(tags)+["nonhtml"])
                        if u in self.state["usersearch_set"]: tags = tuple(list(tags)+["usersearch"])
                        self.domain_tree.insert(iid, "end", iid=node_id, text=display, tags=tags)
                # Insert child segments
                for seg, subtree in sorted((k,v) for k,v in tree.items() if k!="__urls"):
                    seg_iid = f"path::{dom}::{seg}"
                    # create path node and a dummy child if it has further content
                    if not self.domain_tree.exists(seg_iid):
                        self.domain_tree.insert(iid, "end", iid=seg_iid, text=f"/{seg}", open=False)
                        # add dummy if subtree not empty
                        if subtree:
                            dummy_id = f"{seg_iid}::DUMMY"
                            self.domain_tree.insert(seg_iid, "end", iid=dummy_id, text="(loading...)")
        # If it's a path node like path::<domain>::<prefix1>::<prefix2>...
        elif iid.startswith("path::"):
            # path node id format: path::domain::seg1::seg2::...  - extract domain and segments
            parts = iid.split("::")
            # parts[0] == 'path'
            if len(parts) >= 3:
                dom = parts[1]
                segs = parts[2:]
                # check dummy child
                children = self.domain_tree.get_children(iid)
                if len(children) == 1 and children[0].endswith("::DUMMY"):
                    # remove dummy
                    for ch in children:
                        self.domain_tree.delete(ch)
                    # locate subtree in cached tree
                    tree = self._domain_tree_data.get(dom, {})
                    node = tree
                    for s in segs:
                        node = node.get(s, {})
                    # insert any urls at this node
                    urls_here = sorted(node.get("__urls", []))
                    for u in urls_here:
                        node_id = f"url::{u}"
                        if not self.domain_tree.exists(node_id):
                            try:
                                parsed = urlparse(u)
                                display = parsed.path if parsed.path and parsed.path!="/" else u
                            except Exception:
                                display = u
                            tags = ()
                            if u in self.state["non_html_set"]: tags = tuple(list(tags)+["nonhtml"])
                            if u in self.state["usersearch_set"]: tags = tuple(list(tags)+["usersearch"])
                            self.domain_tree.insert(iid, "end", iid=node_id, text=display, tags=tags)
                    # insert deeper segment nodes
                    for child_seg, child_sub in sorted((k,v) for k,v in node.items() if k!="__urls"):
                        child_iid = f"{iid}::{child_seg}"
                        if not self.domain_tree.exists(child_iid):
                            self.domain_tree.insert(iid, "end", iid=child_iid, text=f"/{child_seg}", open=False)
                            # if deeper content, add dummy child
                            if child_sub:
                                dummy_id = f"{child_iid}::DUMMY"
                                self.domain_tree.insert(child_iid, "end", iid=dummy_id, text="(loading...)")
        # else if it's a url node, nothing to do (it's a leaf)

    # ---------- Right-click handling ----------
    def on_domain_right_click(self, event):
        iid = self.domain_tree.identify_row(event.y)
        if not iid:
            return
        # allow right click on domain nodes or url nodes or path nodes
        if iid.startswith("dom::"):
            dom = iid[len("dom::"):]
            url = dom
            is_domain=True
        elif iid.startswith("url::"):
            url = iid[len("url::"):]
            is_domain=False
        elif iid.startswith("path::"):
            # path node -> reconstruct a representative url (base domain + path)
            parts = iid.split("::")
            dom = parts[1]
            segs = parts[2:]
            path = "/" + "/".join(segs)
            url = dom + path
            is_domain=False
        else:
            return

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy link as text", command=lambda u=url: self._copy_link(u))
        menu.add_command(label="Open in browser", command=lambda u=url: self._open_link_with_warn(u))
        menu.add_separator()
        menu.add_command(label="Visit this link (top of queue)", command=lambda u=url: self._visit_this_link(u))
        menu.add_command(label="Visit all the children (top of queue)", command=lambda u=url, is_dom=is_domain: self._visit_all_children(u, is_dom))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_link(self, url):
        try:
            self.root.clipboard_clear(); self.root.clipboard_append(url)
            self._text_insert(f"[COPY] {url}")
        except Exception as e:
            self._text_insert(f"[COPY-ERROR] {e}")

    def _open_link_with_warn(self, url):
        with self.state["lock"]:
            is_nonhtml = url in self.state["non_html_set"]
        if not is_nonhtml:
            webbrowser.open(url); self._text_insert(f"[OPEN] {url}"); return
        dlg = ForceChoiceDialog(self.root, "Open non-HTML link?", f"This link is not an HTML page.\n\nOpen anyway?\n\n{url}")
        self.root.wait_window(dlg)
        choice = dlg.result
        if choice=="yes":
            webbrowser.open(url); self._text_insert(f"[OPEN] {url}")
        elif choice=="no":
            self._text_insert(f"[OPEN-DECLINED] {url}")
        else:
            self._text_insert(f"[OPEN-CANCELLED] {url}")

    def _visit_this_link(self, url):
        # ensure not visited already, then put to front of queue
        with self.state["lock"]:
            if url not in self.state["visited"] and url not in self.state["pending_set"]:
                # add to left
                self.state["pending_queue"].appendleft(url)
                self.state["pending_set"].add(url)
            elif url not in self.state["visited"] and url in self.state["pending_set"]:
                # move existing to front: remove one occurrence in queue and re-add left
                try:
                    self.state["pending_queue"].remove(url)
                except ValueError:
                    pass
                self.state["pending_queue"].appendleft(url)
            # mark as usersearch for highlight
            self.state["usersearch_set"].add(url)
        self._text_insert(f"[USER SEARCH] queued at top: {url}")
        # reflect in UI counts
        with self.state["lock"]:
            self.inqueue_var.set(len(self.state["pending_queue"])); self.discovered_var.set(len(self.state["visited"])+len(self.state["pending_set"]))
        # update domain viewer and queue viewer
        self.root.after(50, self.refresh_domain_view)
        if self.queue_auto_var.get():
            self.refresh_queue_view()

    def _visit_all_children(self, url, is_domain):
        # gather children list: if domain -> all urls under that domain
        to_visit = []
        with self.state["lock"]:
            if is_domain:
                dk = url  # domain key already full like "https://example.com"
                urls = sorted(self.state["domain_map"].get(dk, []))
                to_visit = urls[:]
            else:
                parsed = urlparse(url)
                dk = f"{parsed.scheme}://{parsed.netloc}"
                base_path = parsed.path.rstrip("/")
                candidates = sorted(self.state["domain_map"].get(dk, []))
                for u in candidates:
                    try:
                        pu = urlparse(u)
                        if pu.path.startswith(base_path):
                            to_visit.append(u)
                    except Exception:
                        continue
            # dedupe while preserving order
            seen = set(); deduped = []
            for u in to_visit:
                if u not in seen:
                    deduped.append(u); seen.add(u)
            to_visit = deduped
            # add to front in reverse so first in list is next popped
            for u in reversed(to_visit):
                if u not in self.state["visited"] and u not in self.state["pending_set"]:
                    self.state["pending_queue"].appendleft(u)
                    self.state["pending_set"].add(u)
                elif u not in self.state["visited"] and u in self.state["pending_set"]:
                    try:
                        self.state["pending_queue"].remove(u)
                    except ValueError:
                        pass
                    self.state["pending_queue"].appendleft(u)
            # mark all as usersearch
            for u in to_visit:
                self.state["usersearch_set"].add(u)
        self._text_insert(f"[USER SEARCH] queued {len(to_visit)} children of {url}")
        with self.state["lock"]:
            self.inqueue_var.set(len(self.state["pending_queue"])); self.discovered_var.set(len(self.state["visited"])+len(self.state["pending_set"]))
        self.root.after(50, self.refresh_domain_view)
        if self.queue_auto_var.get():
            self.refresh_queue_view()

    # ---------- Queue Viewer ----------
    def refresh_queue_view(self):
        # snapshot top N queue entries and display them (non-blocking)
        def snapshot_and_update():
            with self.state["lock"]:
                qlist = list(self.state["pending_queue"])
                usersearch = set(self.state["usersearch_set"])
            # top N
            n = max(10, min(250, int(self.queue_show_var.get())))
            topn = qlist[:n]
            # format lines
            lines = []
            for i, u in enumerate(topn, start=1):
                prefix = f"{i:3d}. "
                mark = " [user search]" if u in usersearch else ""
                lines.append(prefix + u + mark)
            # update UI on main thread
            def do_update():
                # update in-tab view
                try:
                    self.queue_text.config(state=tk.NORMAL)
                    self.queue_text.delete(1.0, tk.END)
                    for line in lines:
                        if line.endswith("[user search]"):
                            # insert with yellow highlight
                            self.queue_text.insert(tk.END, line + "\n", ("usersearch",))
                        else:
                            self.queue_text.insert(tk.END, line + "\n")
                    self.queue_text.see("1.0")
                    self.queue_text.config(state=tk.DISABLED)
                except Exception:
                    pass
                # if undocked window exists, update its text widget too
                if self.queue_undocked_text:
                    try:
                        self.queue_undocked_text.config(state=tk.NORMAL)
                        self.queue_undocked_text.delete(1.0, tk.END)
                        for line in lines:
                            if line.endswith("[user search]"):
                                self.queue_undocked_text.insert(tk.END, line + "\n", ("usersearch",))
                            else:
                                self.queue_undocked_text.insert(tk.END, line + "\n")
                        self.queue_undocked_text.see("1.0")
                        self.queue_undocked_text.config(state=tk.DISABLED)
                    except Exception:
                        pass
            self.root.after(10, do_update)
        threading.Thread(target=snapshot_and_update, daemon=True).start()

    def toggle_queue_undock(self):
        # If undocked exists, close it (dock back). Otherwise, create undocked window.
        if self.queue_undocked_win:
            try:
                self.queue_undocked_win.destroy()
            except Exception:
                pass
            self.queue_undocked_win = None
            self.queue_undocked_text = None
            self.queue_undock_btn.config(text="Undock")
            return
        # create new top-level window
        win = tk.Toplevel(self.root)
        win.title("Queue Viewer (Undocked)")
        win.geometry("800x600")
        frm = ttk.Frame(win); frm.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        txt = scrolledtext.ScrolledText(frm, wrap=tk.NONE)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.tag_config("usersearch", background="yellow")
        txt.config(state=tk.DISABLED)
        # store
        self.queue_undocked_win = win
        self.queue_undocked_text = txt
        self.queue_undock_btn.config(text="Dock")
        # when undocked window closes, clear references and update button
        def on_close():
            self.queue_undocked_win = None
            self.queue_undocked_text = None
            try:
                self.queue_undock_btn.config(text="Undock")
            except Exception:
                pass
            try:
                win.destroy()
            except Exception:
                pass
        win.protocol("WM_DELETE_WINDOW", on_close)
        # initial refresh to populate window
        self.refresh_queue_view()

    # ---------- Filtering / Search for Log (unchanged) ----------
    def _apply_log_filter(self):
        if not hasattr(self, "_log_history"):
            self._log_history = []
        s = self.log_search_var.get().lower().strip()
        filt = self.log_filter_var.get()
        self.text_box.config(state=tk.NORMAL); self.text_box.delete(1.0, tk.END)
        for entry in self._log_history:
            text, is_nonhtml, is_user = entry
            ok = True
            if s and s not in text.lower(): ok = False
            if filt=="HTML only" and is_nonhtml: ok = False
            if filt=="Non-HTML only" and not is_nonhtml: ok = False
            if ok:
                tags = ()
                if is_nonhtml: tags = ("nonhtml",)
                if is_user: tags = tuple(list(tags)+["usersearch"])
                if tags:
                    self.text_box.insert(tk.END, text + "\n", tags)
                else:
                    self.text_box.insert(tk.END, text + "\n")
        self.text_box.see(tk.END)
        self.text_box.config(state=tk.DISABLED)

    def _append_log_history(self, text, is_nonhtml=False, is_user=False):
        if not hasattr(self, "_log_history"):
            self._log_history = []
        self._log_history.append((text, is_nonhtml, is_user))
        if len(self._log_history) > 20000:
            self._log_history.pop(0)

    def _apply_domain_filter(self):
        # manual refresh only
        self.refresh_domain_view()

    # ---------- UI polling ----------
    def _poll_ui(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if not item: continue
                typ = item[0]
                if typ=="visited":
                    _, url, count = item
                    with self.state["lock"]:
                        is_non = url in self.state["non_html_set"]
                        is_user = url in self.state["usersearch_set"]
                        inqueue = len(self.state["pending_queue"])
                        discovered_total = len(self.state["visited"]) + len(self.state["pending_set"])
                    t = f"Visited link: {url}"
                    if is_user: t += "   [user search]"
                    if is_non: t += "   (non-html)"
                    self._append_log_history(t, is_nonhtml=is_non, is_user=is_user)
                    show = True
                    s = self.log_search_var.get().lower().strip()
                    filt = self.log_filter_var.get()
                    if s and s not in t.lower(): show=False
                    if filt=="HTML only" and is_non: show=False
                    if filt=="Non-HTML only" and not is_non: show=False
                    if show:
                        tags = ()
                        if is_non: tags = ("nonhtml",)
                        if is_user: tags = tuple(list(tags)+["usersearch"])
                        self._text_insert(t, tags=tags)
                    self.visited_var.set(count); self.inqueue_var.set(inqueue); self.discovered_var.set(discovered_total)
                    self.status_var.set(f"Visited: {count}")
                    # Trigger queue refresh when visited occurs (a queue item solved). Respect Auto Refresh toggle.
                    if self.queue_auto_var.get():
                        self.refresh_queue_view()
                elif typ=="discovered":
                    _, last_url, discovered_total = item
                    with self.state["lock"]:
                        is_non = last_url in self.state["non_html_set"]
                        is_user = last_url in self.state["usersearch_set"]
                        inqueue = len(self.state["pending_queue"])
                    t = f"Discovered: {last_url}"
                    if is_user: t += "   [user search]"
                    if is_non: t += "   (non-html)"
                    self._append_log_history(t, is_nonhtml=is_non, is_user=is_user)
                    s = self.log_search_var.get().lower().strip()
                    filt = self.log_filter_var.get()
                    show = True
                    if s and s not in t.lower(): show=False
                    if filt=="HTML only" and is_non: show=False
                    if filt=="Non-HTML only" and not is_non: show=False
                    if show:
                        tags = ()
                        if is_non: tags = ("nonhtml",)
                        if is_user: tags = tuple(list(tags)+["usersearch"])
                        self._text_insert(t, tags=tags)
                    self.last_discovered_var.set(last_url)
                    self.discovered_var.set(discovered_total)
                    self.inqueue_var.set(inqueue)
                    # a new URL discovered changes queue; update queue view if auto on
                    if self.queue_auto_var.get():
                        self.refresh_queue_view()
                elif typ=="note_nonhtml":
                    _, url, ctype = item
                    with self.state["lock"]:
                        self.state["non_html_set"].add(url)
                    t = f"Visited link: {url}  |  skipped non-html ({ctype})"
                    self._append_log_history(t, is_nonhtml=True, is_user=(url in self.state["usersearch_set"]))
                    s = self.log_search_var.get().lower().strip(); filt = self.log_filter_var.get()
                    show=True
                    if s and s not in t.lower(): show=False
                    if filt=="HTML only": show=False
                    if filt=="Non-HTML only" and not True: show=False
                    if show:
                        self._text_insert(t, tags=("nonhtml",))
                    # this is effectively a visited event (non-html), so refresh queue if auto
                    if self.queue_auto_var.get():
                        self.refresh_queue_view()
                elif typ=="counts":
                    _, discovered_total, visited_count = item
                    self.discovered_var.set(discovered_total); self.visited_var.set(visited_count)
                    with self.state["lock"]:
                        self.inqueue_var.set(len(self.state["pending_queue"]))
                elif typ in ("note","info","error"):
                    key, msg = item[0], item[1]
                    self._append_log_history(msg, is_nonhtml=False, is_user=False)
                    self._text_insert(f"[{key.upper()}] {msg}")
                elif typ=="finished":
                    _, total = item
                    self._text_insert(f"[FINISHED] visited {total} pages.")
                    self.status_var.set("Finished")
                    self.btn_start.config(state=tk.NORMAL); self.btn_stop.config(state=tk.DISABLED); self.btn_pause.config(state=tk.DISABLED); self.btn_import.config(state=tk.NORMAL)
                    # final queue update
                    self.refresh_queue_view()
                else:
                    self._text_insert(f"[MSG] {item}")
        except Empty:
            pass
        self.root.after(150, self._poll_ui)

# ---------- run ----------
if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    try: style.theme_use("clam")
    except Exception: pass
    app = CrawlerApp(root)
    root.mainloop()
