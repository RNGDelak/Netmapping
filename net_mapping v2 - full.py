#!/usr/bin/env python3
"""
Merged crawler with full Domain Viewer, Queue Viewer, Mark Manager, Font slider, Filters, and Import/Export.
This file preserves the original crawler behavior and adds requested UI features.
Requirements: requests, beautifulsoup4
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
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog

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

        # Font size slider (global)
        ttk.Label(top, text="Font (px):").grid(row=0,column=4,sticky=tk.E)
        self.font_size = tk.IntVar(value=9)
        self.font_slider = ttk.Scale(top, from_=1, to=25, orient=tk.HORIZONTAL, command=self._on_font_slider, length=140)
        self.font_slider.set(self.font_size.get()); self.font_slider.grid(row=0,column=5,sticky=tk.W,padx=(6,6))
        self.font_label = ttk.Label(top, text=f"{self.font_size.get()} px"); self.font_label.grid(row=0,column=6,sticky=tk.W)

        # Delay
        ttk.Label(top, text="Delay (ms):").grid(row=1,column=0,sticky=tk.W,pady=(6,0))
        self.delay_ms = tk.IntVar(value=50)
        self.delay_slider = ttk.Scale(top, from_=1, to=5000, orient=tk.HORIZONTAL, command=self._on_slider_move, length=300)
        self.delay_slider.set(self.delay_ms.get()); self.delay_slider.grid(row=1,column=1,sticky=tk.W,pady=(6,0))
        self.delay_label = ttk.Label(top, text=f"{self.delay_ms.get()} ms"); self.delay_label.grid(row=1,column=2,sticky=tk.W,padx=(6,0),pady=(6,0))

        # Buttons
        self.btn_start = ttk.Button(top, text="Start Crawl", command=self.start_crawl); self.btn_start.grid(row=0,column=7,padx=(8,0))
        self.btn_pause = ttk.Button(top, text="Pause", command=self.toggle_pause, state=tk.DISABLED); self.btn_pause.grid(row=0,column=8,padx=(6,0))
        self.btn_stop = ttk.Button(top, text="Stop", command=self.stop_crawl, state=tk.DISABLED); self.btn_stop.grid(row=0,column=9,padx=(6,0))
        self.btn_import = ttk.Button(top, text="Import JSON", command=self.import_json); self.btn_import.grid(row=1,column=7,padx=(8,0))
        self.btn_export = ttk.Button(top, text="Export JSON", command=self.export_json); self.btn_export.grid(row=1,column=8,padx=(6,0))

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

        # Search controls (case-sensitive exact)
        ttk.Label(domain_top, text="Search (case-sensitive):").pack(side=tk.LEFT)
        self.dom_search_var = tk.StringVar()
        self.dom_search_entry = ttk.Entry(domain_top, textvariable=self.dom_search_var, width=30)
        self.dom_search_entry.pack(side=tk.LEFT, padx=(6,4))
        self.dom_search_btn = ttk.Button(domain_top, text="Find", command=self.domain_search_do); self.dom_search_btn.pack(side=tk.LEFT, padx=(2,6))
        self.dom_clearsearch_btn = ttk.Button(domain_top, text="Clear", command=self.domain_search_clear); self.dom_clearsearch_btn.pack(side=tk.LEFT, padx=(0,6))

        # A/B display toggle
        self.display_mode = tk.StringVar(value="A")
        ttk.Label(domain_top, text="Display:").pack(side=tk.LEFT)
        self.display_combo = ttk.Combobox(domain_top, textvariable=self.display_mode, values=["A","B"], width=3, state="readonly")
        self.display_combo.pack(side=tk.LEFT, padx=(4,8))
        ttk.Label(domain_top, text="(A=path, B=full URL)").pack(side=tk.LEFT, padx=(0,8))

        # Subdomain count toggle (hidden default)
        self.show_subdomain_counts = tk.BooleanVar(value=False)
        self.subdomain_check = ttk.Checkbutton(domain_top, text="Show subdomain counts", variable=self.show_subdomain_counts, command=self._on_subdomain_toggle)
        self.subdomain_check.pack(side=tk.LEFT, padx=(0,8))

        # Mark controls (dropdown + teleport)
        ttk.Label(domain_top, text="Marks:").pack(side=tk.LEFT)
        self.mark_combo = ttk.Combobox(domain_top, values=[], width=25, state="readonly")
        self.mark_combo.pack(side=tk.LEFT, padx=(4,4))
        self.teleport_btn = ttk.Button(domain_top, text="Teleport to mark", command=self._teleport_to_selected_mark); self.teleport_btn.pack(side=tk.LEFT, padx=(2,6))

        # Filter button
        self.filter_btn = ttk.Button(domain_top, text="Filter", command=self._open_filter_popup); self.filter_btn.pack(side=tk.LEFT, padx=(4,6))

        # Refresh
        self.btn_domain_refresh = ttk.Button(domain_top, text="Refresh", command=self.refresh_domain_view); self.btn_domain_refresh.pack(side=tk.LEFT, padx=(8,0))
        ttk.Label(domain_top, text="(starts collapsed, alphabetical)").pack(side=tk.LEFT, padx=(8,0))

        # Treeview area
        tree_frame = ttk.Frame(self.tab_domain); tree_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
        self.domain_tree = ttk.Treeview(tree_frame, show="tree")
        self.domain_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.domain_tree.yview); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.domain_tree.configure(yscrollcommand=vsb.set)
        # horizontal scrollbar moved below to make it easier to grab (spans the width)
        self.domain_tree_hscroll = ttk.Scrollbar(self.tab_domain, orient="horizontal", command=self.domain_tree.xview)
        self.domain_tree.configure(xscrollcommand=self.domain_tree_hscroll.set)
        self.domain_tree_hscroll.pack(side=tk.BOTTOM, fill=tk.X, padx=6)  # placed under the tab area

        # bind right-click and expansion
        self.domain_tree.bind("<Button-3>", self.on_domain_right_click)
        self.domain_tree.bind("<Control-Button-1>", self.on_domain_right_click)
        self.domain_tree.bind("<<TreeviewOpen>>", self._on_tree_open)

        # tag config
        try: self.domain_tree.tag_configure("nonhtml", foreground="red")
        except Exception: pass
        try: self.domain_tree.tag_configure("notvisited", foreground="#9a9a9a")
        except Exception: pass
        try: self.domain_tree.tag_configure("searchmatch", background="yellow")
        except Exception: pass
        try: self.domain_tree.tag_configure("marked", background="#d7f0ff")  # light blue highlight (marked)
        except Exception: pass

        self.notebook.add(self.tab_domain, text="Domain Viewer")

        # Tab: Queue Viewer
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
        # Manual Refresh button
        self.queue_refresh_btn = ttk.Button(q_top, text="Refresh", command=self.refresh_queue_view); self.queue_refresh_btn.pack(side=tk.LEFT, padx=(0,8))

        # queue display area
        queue_frame = ttk.Frame(self.tab_queue); queue_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
        self.queue_text = scrolledtext.ScrolledText(queue_frame, width=110, height=30, wrap=tk.NONE)
        qhsb = ttk.Scrollbar(queue_frame, orient="horizontal", command=self.queue_text.xview); qhsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.queue_text.configure(xscrollcommand=qhsb.set)
        self.queue_text.pack(fill=tk.BOTH, expand=True)
        self.queue_text.tag_config("usersearch", background="yellow")
        self.queue_text.config(state=tk.DISABLED)
        self.notebook.add(self.tab_queue, text="Queue Viewer")

        # Tab: Mark Manager
        self.tab_marks = ttk.Frame(self.notebook)
        marks_top = ttk.Frame(self.tab_marks); marks_top.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(marks_top, text="Marks (rename/delete):").pack(side=tk.LEFT)
        # marks list box area (use scrolledtext style but will be non-editable)
        marks_frame = ttk.Frame(self.tab_marks); marks_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
        self.marks_list = tk.Listbox(marks_frame, selectmode=tk.BROWSE, exportselection=False)
        self.marks_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        m_vsb = ttk.Scrollbar(marks_frame, orient="vertical", command=self.marks_list.yview); m_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.marks_list.configure(yscrollcommand=m_vsb.set)
        # buttons below
        marks_btns = ttk.Frame(self.tab_marks); marks_btns.pack(fill=tk.X, padx=6, pady=(4,6))
        self.rename_mark_btn = ttk.Button(marks_btns, text="Rename", command=self._rename_mark); self.rename_mark_btn.pack(side=tk.LEFT, padx=6)
        self.delete_mark_btn = ttk.Button(marks_btns, text="Delete", command=self._delete_mark); self.delete_mark_btn.pack(side=tk.LEFT, padx=6)
        self.goto_mark_btn = ttk.Button(marks_btns, text="Teleport to mark", command=self._teleport_mark_from_manager); self.goto_mark_btn.pack(side=tk.LEFT, padx=6)
        self.notebook.add(self.tab_marks, text="Mark Manager")

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

        # cached domain tree data for manual refresh (domain -> nested dict)
        self._domain_tree_data = {}
        # marks: name -> url
        self.marks = {}

        # log history
        self._log_history = []

        # poll UI
        self.root.after(150, self._poll_ui)

    # ---------- helpers ----------
    def _on_font_slider(self, value):
        try:
            v = int(float(value))
        except Exception:
            v = self.font_size.get()
        self.font_size.set(v)
        try:
            self.font_label.config(text=f"{v} px")
        except Exception:
            pass
        # apply font size to text widgets and listbox
        f = ("TkDefaultFont", v)
        try:
            self.text_box.config(font=f)
        except Exception: pass
        try:
            self.queue_text.config(font=f)
        except Exception: pass
        try:
            self.marks_list.config(font=f)
        except Exception: pass
        # domain tree font setting is not straightforward; attempt to set ttk style
        try:
            style = ttk.Style()
            style.configure("Treeview", font=f)
        except Exception:
            pass

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
        # keep history
        self._append_log_history(text, is_nonhtml=False, is_user=False)

    # ---------- controls ----------
    def start_crawl(self):
        seed = self.url_var.get().strip()
        if not seed:
            messagebox.showwarning("No URL", "Please enter a seed URL."); return
        p = urlparse(seed)
        if not p.scheme: seed = "http://" + seed
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Already running", "Crawler is already running."); return

        # reset UI/state (preserve marks)
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
        data = {"visited": visited_list, "discovered": pending_list, "non_html": nonhtml_list, "usersearch": usersearch_list, "marks": self.marks}
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
            marks = data.get("marks", {})
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
        # restore marks
        try:
            self.marks = dict(marks)
            self._update_marks_dropdown()
            self._rebuild_marks_listbox()
        except Exception:
            pass
        self._text_insert(f"[IMPORT] Loaded session from: {fname}")
        self.visited_var.set(len(self.state["visited"])); self.inqueue_var.set(len(self.state["pending_queue"])); self.discovered_var.set(len(self.state["visited"])+len(self.state["pending_set"]))
        self.last_discovered_var.set(discovered[-1] if discovered else "")
        # clear domain cache to ensure rebuilt on next refresh
        self._domain_tree_data.clear()

    # ---------- Domain Viewer rebuild (manual only) ----------
    def refresh_domain_view(self):
        self.btn_domain_refresh.config(state=tk.DISABLED)
        def snapshot():
            with self.state["lock"]:
                snap = {dom: sorted(list(urls)) for dom,urls in self.state["domain_map"].items()}
                nonhtml_snapshot = set(self.state["non_html_set"])
                usersearch_snapshot = set(self.state["usersearch_set"])
                visited_snapshot = set(self.state["visited"])
            # build nested per-domain trees
            dom_trees = {}
            for dom, urls in snap.items():
                tree = {}
                for u in urls:
                    parsed = urlparse(u)
                    path = parsed.path or "/"
                    if path=="" or path=="/":
                        tree.setdefault("__urls", set()).add(u)
                        continue
                    segments = [seg for seg in path.split("/") if seg!='']
                    node = tree
                    for seg in segments:
                        node = node.setdefault(seg, {})
                    node.setdefault("__urls", set()).add(u)
                dom_trees[dom] = tree
            self.root.after(10, lambda: self._populate_domain_tree_incremental(dom_trees, nonhtml_snapshot, usersearch_snapshot, visited_snapshot))
        threading.Thread(target=snapshot,daemon=True).start()

    def _populate_domain_tree_incremental(self, dom_trees, nonhtml_snapshot, usersearch_snapshot, visited_snapshot):
        # clear
        for iid in self.domain_tree.get_children(): self.domain_tree.delete(iid)
        self._domain_tree_data = dom_trees
        # Insert domain nodes collapsed, add dummy child
        for dom in sorted(dom_trees.keys()):
            node_id = f"dom::{dom}"
            if not self.domain_tree.exists(node_id):
                display = dom
                # append subdomain count inline if toggled
                if self.show_subdomain_counts.get():
                    base_host = urlparse(dom).netloc.lower()
                    cnt = 0
                    for d in dom_trees.keys():
                        h = urlparse(d).netloc.lower()
                        if h != base_host and h.endswith("." + base_host):
                            cnt += 1
                    display = f"{dom}    ({cnt})"
                self.domain_tree.insert("", "end", iid=node_id, text=display, open=False)
                dummy_id = f"{node_id}::DUMMY"
                if not self.domain_tree.exists(dummy_id):
                    self.domain_tree.insert(node_id, "end", iid=dummy_id, text="(loading...)")
        self.btn_domain_refresh.config(state=tk.NORMAL)

    def _on_tree_open(self, event):
        iid = self.domain_tree.focus()
        if not iid:
            return
        # domain root
        if iid.startswith("dom::"):
            dom = iid[len("dom::"):]
            children = self.domain_tree.get_children(iid)
            if len(children) == 1 and children[0].endswith("::DUMMY"):
                for ch in children: self.domain_tree.delete(ch)
                tree = self._domain_tree_data.get(dom, {})
                # root urls
                for u in sorted(tree.get("__urls", [])):
                    node_id = f"url::{u}"
                    if not self.domain_tree.exists(node_id):
                        display = "/" if urlparse(u).path in ("", "/") else urlparse(u).path
                        tags = self._node_tags_for(u)
                        self.domain_tree.insert(iid, "end", iid=node_id, text=display, tags=tags)
                # top-level segments
                for seg in sorted(k for k in tree.keys() if k!="__urls"):
                    seg_iid = f"path::{dom}::{seg}"
                    if not self.domain_tree.exists(seg_iid):
                        self.domain_tree.insert(iid, "end", iid=seg_iid, text=f"/{seg}", open=False)
                        if tree.get(seg):
                            dummy_id = f"{seg_iid}::DUMMY"
                            self.domain_tree.insert(seg_iid, "end", iid=dummy_id, text="(loading...)")
        elif iid.startswith("path::"):
            parts = iid.split("::")
            if len(parts) >= 3:
                dom = parts[1]; segs = parts[2:]
                children = self.domain_tree.get_children(iid)
                if len(children) == 1 and children[0].endswith("::DUMMY"):
                    for ch in children: self.domain_tree.delete(ch)
                    tree = self._domain_tree_data.get(dom, {})
                    node = tree
                    for s in segs:
                        node = node.get(s, {})
                    for u in sorted(node.get("__urls", [])):
                        node_id = f"url::{u}"
                        if not self.domain_tree.exists(node_id):
                            display = urlparse(u).path if urlparse(u).path and urlparse(u).path != "/" else u
                            tags = self._node_tags_for(u)
                            self.domain_tree.insert(iid, "end", iid=node_id, text=display, tags=tags)
                    for child_seg in sorted(k for k in node.keys() if k!="__urls"):
                        child_iid = f"{iid}::{child_seg}"
                        if not self.domain_tree.exists(child_iid):
                            self.domain_tree.insert(iid, "end", iid=child_iid, text=f"/{child_seg}", open=False)
                            if node.get(child_seg):
                                dummy_id = f"{child_iid}::DUMMY"
                                self.domain_tree.insert(child_iid, "end", iid=dummy_id, text="(loading...)")

    def _node_tags_for(self, url):
        tags = []
        if url in self.state["non_html_set"]:
            tags.append("nonhtml")
            return tuple(tags)
        if url not in self.state["visited"]:
            tags.append("notvisited")
        # if marked -> apply marked tag (marked overrides search highlight later)
        for name,u in self.marks.items():
            if u == url:
                tags.append("marked")
                break
        return tuple(tags)

    # ---------- Right-click handling + mark ----------
    def on_domain_right_click(self, event):
        iid = self.domain_tree.identify_row(event.y)
        if not iid:
            return
        if iid.startswith("dom::"):
            dom = iid[len("dom::"):]
            url = dom; is_domain=True
        elif iid.startswith("url::"):
            url = iid[len("url::"):]; is_domain=False
        elif iid.startswith("path::"):
            parts = iid.split("::")
            dom = parts[1]; segs = parts[2:]; url = dom + "/" + "/".join(segs); is_domain=False
        else:
            return

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy link as text", command=lambda u=url: self._copy_link(u))
        menu.add_command(label="Open in browser", command=lambda u=url: self._open_link_with_warn(u))
        menu.add_separator()
        menu.add_command(label="Visit this link (top of queue)", command=lambda u=url: self._visit_this_link(u))
        menu.add_command(label="Visit all the children (top of queue)", command=lambda u=url, is_dom=is_domain: self._visit_all_children(u, is_dom))
        menu.add_separator()
        menu.add_command(label="Mark this link", command=lambda u=url: self._mark_this_link(u))
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
        with self.state["lock"]:
            if url not in self.state["visited"] and url not in self.state["pending_set"]:
                self.state["pending_queue"].appendleft(url); self.state["pending_set"].add(url)
            elif url not in self.state["visited"] and url in self.state["pending_set"]:
                try: self.state["pending_queue"].remove(url)
                except ValueError: pass
                self.state["pending_queue"].appendleft(url)
            self.state["usersearch_set"].add(url)
        self._text_insert(f"[USER SEARCH] queued at top: {url}")
        with self.state["lock"]:
            self.inqueue_var.set(len(self.state["pending_queue"])); self.discovered_var.set(len(self.state["visited"])+len(self.state["pending_set"]))
        if self.queue_auto_var.get(): self.refresh_queue_view()

    def _visit_all_children(self, url, is_domain):
        to_visit=[]
        with self.state["lock"]:
            if is_domain:
                dk = url
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
                        if pu.path.startswith(base_path): to_visit.append(u)
                    except Exception: continue
            seen=set(); dedup=[]
            for u in to_visit:
                if u not in seen:
                    dedup.append(u); seen.add(u)
            to_visit=dedup
            for u in reversed(to_visit):
                if u not in self.state["visited"] and u not in self.state["pending_set"]:
                    self.state["pending_queue"].appendleft(u); self.state["pending_set"].add(u)
                elif u not in self.state["visited"] and u in self.state["pending_set"]:
                    try: self.state["pending_queue"].remove(u)
                    except Exception: pass
                    self.state["pending_queue"].appendleft(u)
            for u in to_visit: self.state["usersearch_set"].add(u)
        self._text_insert(f"[USER SEARCH] queued {len(to_visit)} children of {url}")
        with self.state["lock"]:
            self.inqueue_var.set(len(self.state["pending_queue"])); self.discovered_var.set(len(self.state["visited"])+len(self.state["pending_set"]))
        if self.queue_auto_var.get(): self.refresh_queue_view()

    # ---------- Marking ----------
    def _mark_this_link(self, url):
        default = urlparse(url).path if self.display_mode.get()=="A" and urlparse(url).path and urlparse(url).path!="/" else url
        name = simpledialog.askstring("Mark this link", "Enter mark name:", initialvalue=default, parent=self.root)
        if not name: return
        self.marks[name] = url
        self._update_marks_dropdown()
        self._rebuild_marks_listbox()
        # update domain tree item's tag to marked (if present)
        iid = f"url::{url}"
        if self.domain_tree.exists(iid):
            try:
                tags = list(self.domain_tree.item(iid).get("tags",()))
                if "marked" not in tags:
                    tags.append("marked")
                    self.domain_tree.item(iid, tags=tuple(tags))
            except Exception: pass
        self._text_insert(f"[MARK] '{name}' -> {url}")

    def _update_marks_dropdown(self):
        try:
            names = sorted(self.marks.keys())
            self.mark_combo.config(values=names)
            if names:
                self.mark_combo.set(names[0])
        except Exception:
            pass

    def _rebuild_marks_listbox(self):
        try:
            self.marks_list.delete(0, tk.END)
            for name in sorted(self.marks.keys()):
                self.marks_list.insert(tk.END, f"{name} -> {self.marks[name]}")
        except Exception:
            pass

    def _teleport_to_selected_mark(self):
        sel = self.mark_combo.get()
        if not sel:
            messagebox.showinfo("No mark selected", "Please pick a mark from the dropdown."); return
        url = self.marks.get(sel)
        if not url:
            messagebox.showerror("Mark missing", "Selected mark not found."); return
        ok = self._teleport_to_url(url)
        if not ok:
            messagebox.showinfo("Teleport unavailable", "Domain data not present for this mark. Please click Refresh in Domain Viewer and try again.")

    def _teleport_mark_from_manager(self):
        sel_index = self.marks_list.curselection()
        if not sel_index:
            messagebox.showinfo("No mark selected", "Select a mark in Mark Manager first."); return
        entry = self.marks_list.get(sel_index[0])
        name = entry.split(" -> ",1)[0]
        url = self.marks.get(name)
        if not url:
            messagebox.showerror("Mark missing", "Mark data missing."); return
        ok = self._teleport_to_url(url)
        if not ok:
            messagebox.showinfo("Teleport unavailable", "Domain data not present. Please click Refresh first.")

    def _rename_mark(self):
        sel_index = self.marks_list.curselection()
        if not sel_index:
            messagebox.showinfo("Select mark", "Please select a mark to rename."); return
        entry = self.marks_list.get(sel_index[0])
        old_name = entry.split(" -> ",1)[0]
        url = self.marks.get(old_name)
        new_name = simpledialog.askstring("Rename mark", "Enter new name:", initialvalue=old_name, parent=self.root)
        if not new_name: return
        # rename safely, avoid key collisions
        del self.marks[old_name]; self.marks[new_name] = url
        self._update_marks_dropdown(); self._rebuild_marks_listbox()
        self._text_insert(f"[MARK-RENAMED] '{old_name}' -> '{new_name}'")

    def _delete_mark(self):
        sel_index = self.marks_list.curselection()
        if not sel_index:
            messagebox.showinfo("Select mark", "Please select a mark to delete."); return
        entry = self.marks_list.get(sel_index[0])
        name = entry.split(" -> ",1)[0]
        confirm = messagebox.askyesno("Delete mark", f"Delete mark '{name}'?")
        if not confirm: return
        url = self.marks.pop(name, None)
        self._update_marks_dropdown(); self._rebuild_marks_listbox()
        # remove 'marked' tag from tree if present
        if url:
            iid = f"url::{url}"
            if self.domain_tree.exists(iid):
                try:
                    tags = list(self.domain_tree.item(iid).get("tags",()))
                    if "marked" in tags:
                        tags.remove("marked")
                        self.domain_tree.item(iid, tags=tuple(tags))
                except Exception: pass
        self._text_insert(f"[MARK-DELETED] '{name}'")

    # ---------- Teleport helper ----------
    def _teleport_to_url(self, url):
        parsed = urlparse(url)
        dk = f"{parsed.scheme}://{parsed.netloc}"
        if dk not in self._domain_tree_data:
            return False
        dom_iid = f"dom::{dk}"
        if not self.domain_tree.exists(dom_iid):
            return False
        # open domain and populate
        try:
            self.domain_tree.item(dom_iid, open=True)
            children = self.domain_tree.get_children(dom_iid)
            if len(children)==1 and children[0].endswith("::DUMMY"):
                self.domain_tree.focus(dom_iid); self._on_tree_open(None)
        except Exception: pass
        # walk path
        path = parsed.path or "/"
        if path in ("", "/"):
            target_iid = f"url::{url}"
            if self.domain_tree.exists(target_iid):
                try: self.domain_tree.see(target_iid); self.domain_tree.selection_set(target_iid)
                except Exception: pass
                return True
            return False
        segments = [seg for seg in path.split("/") if seg!='']
        parent = dom_iid
        for i,seg in enumerate(segments):
            if i==0:
                seg_iid = f"path::{dk}::{seg}"
            else:
                prev = "::".join(["path", dk] + segments[:i])
                seg_iid = f"{prev}::{seg}"
            if not self.domain_tree.exists(seg_iid):
                try: self.domain_tree.item(parent, open=True); self.domain_tree.focus(parent); self._on_tree_open(None)
                except Exception: pass
                if not self.domain_tree.exists(seg_iid):
                    return False
            try:
                self.domain_tree.item(seg_iid, open=True)
                children = self.domain_tree.get_children(seg_iid)
                if len(children)==1 and children[0].endswith("::DUMMY"):
                    self.domain_tree.focus(seg_iid); self._on_tree_open(None)
            except Exception: pass
            parent = seg_iid
        target_iid = f"url::{url}"
        if self.domain_tree.exists(target_iid):
            try: self.domain_tree.see(target_iid); self.domain_tree.selection_set(target_iid)
            except Exception: pass
            return True
        return False

    # ---------- Search (case-sensitive exact substring) ----------
    def domain_search_do(self):
        q = self.dom_search_var.get()
        if not q:
            messagebox.showinfo("Empty search", "Please enter a non-empty search string (case-sensitive)."); return
        self._clear_search_highlights()
        matches = []
        for dom, tree in self._domain_tree_data.items():
            def walk(node):
                for k,v in node.items():
                    if k=="__urls":
                        for u in v:
                            if q in u: matches.append((dom,u))
                    else:
                        walk(v)
            walk(tree)
        if not matches:
            messagebox.showinfo("No matches", "No matching URLs found in current domain snapshot.")
            return
        for dom, url in matches:
            success = self._teleport_to_url(url)
            if success:
                iid = f"url::{url}"
                try:
                    existing = list(self.domain_tree.item(iid).get("tags",()))
                    # if marked, marked tag takes precedence (do not add searchmatch)
                    if "marked" in existing:
                        continue
                    if "searchmatch" not in existing:
                        existing.append("searchmatch")
                        self.domain_tree.item(iid, tags=tuple(existing))
                except Exception: pass
        self._text_insert(f"[SEARCH] Found {len(matches)} matches for '{q}' (case-sensitive).")

    def domain_search_clear(self):
        self.dom_search_var.set("")
        self._clear_search_highlights()

    def _clear_search_highlights(self):
        for root in self.domain_tree.get_children():
            for iid in self._iter_all_tree_ids(root):
                try:
                    tags = list(self.domain_tree.item(iid).get("tags",()))
                    if "searchmatch" in tags:
                        tags.remove("searchmatch")
                        self.domain_tree.item(iid, tags=tuple(tags))
                except Exception: pass

    def _iter_all_tree_ids(self, root):
        stack = [root]
        while stack:
            cur = stack.pop()
            yield cur
            for c in self.domain_tree.get_children(cur):
                stack.append(c)

    # ---------- Filter popup ----------
    def _open_filter_popup(self):
        win = tk.Toplevel(self.root)
        win.transient(self.root)
        win.title("Domain Viewer Filters")
        frm = ttk.Frame(win, padding=12); frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text="File Type").grid(row=0,column=0,sticky=tk.W)
        ft = ttk.Combobox(frm, textvariable=tk.StringVar(value=self.filter_filetype.get()), values=["All","HTML only","Non-HTML only"], state="readonly")
        ft.grid(row=0,column=1,sticky=tk.W,padx=8,pady=4)
        ttk.Label(frm, text="Search Origin").grid(row=1,column=0,sticky=tk.W)
        so = ttk.Combobox(frm, textvariable=tk.StringVar(value=self.filter_origin.get()), values=["All","Program search","User search"], state="readonly")
        so.grid(row=1,column=1,sticky=tk.W,padx=8,pady=4)
        ttk.Label(frm, text="Crawl Status").grid(row=2,column=0,sticky=tk.W)
        cs = ttk.Combobox(frm, textvariable=tk.StringVar(value=self.filter_status.get()), values=["All","Visited","Not visited"], state="readonly")
        cs.grid(row=2,column=1,sticky=tk.W,padx=8,pady=4)
        def apply_and_close():
            # copy selections back
            self.filter_filetype.set(ft.get()); self.filter_origin.set(so.get()); self.filter_status.set(cs.get())
            # rebuilding domain tree based on filters requires a refresh snapshot
            self.refresh_domain_view()
            win.destroy()
        btnfrm = ttk.Frame(frm); btnfrm.grid(row=3,column=0,columnspan=2,pady=(8,0))
        ttk.Button(btnfrm, text="Apply", command=apply_and_close).pack(side=tk.LEFT, padx=8)
        ttk.Button(btnfrm, text="Close", command=win.destroy).pack(side=tk.LEFT, padx=8)

    # ---------- Subdomain toggle ----------
    def _on_subdomain_toggle(self):
        if self._domain_tree_data:
            self.refresh_domain_view()

    # ---------- Queue view ----------
    def refresh_queue_view(self):
        def snapshot_and_update():
            with self.state["lock"]:
                qlist = list(self.state["pending_queue"])
                usersearch = set(self.state["usersearch_set"])
            n = max(10, min(250, int(self.queue_show_var.get())))
            topn = qlist[:n]
            lines = []
            for i,u in enumerate(topn, start=1):
                prefix = f"{i:3d}. "
                mark = " [user search]" if u in usersearch else ""
                lines.append(prefix + u + mark)
            def do_update():
                try:
                    self.queue_text.config(state=tk.NORMAL)
                    self.queue_text.delete(1.0, tk.END)
                    for line in lines:
                        if line.endswith("[user search]"):
                            self.queue_text.insert(tk.END, line + "\n", ("usersearch",))
                        else:
                            self.queue_text.insert(tk.END, line + "\n")
                    self.queue_text.see("1.0")
                    self.queue_text.config(state=tk.DISABLED)
                except Exception: pass
            self.root.after(10, do_update)
        threading.Thread(target=snapshot_and_update, daemon=True).start()

    # ---------- UI Polling ----------
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
                    # when visited occurs, update domain tree tags for that url if present
                    iid = f"url::{url}"
                    if self.domain_tree.exists(iid):
                        try:
                            tags = list(self.domain_tree.item(iid).get("tags",()))
                            # remove notvisited if present
                            if "notvisited" in tags: tags.remove("notvisited")
                            # if nonhtml remains, keep it
                            self.domain_tree.item(iid, tags=tuple(tags))
                        except Exception: pass
                    # Trigger queue refresh when visited occurs (a queue item solved). Respect Auto Refresh toggle.
                    if getattr(self, "queue_auto_var", None) and self.queue_auto_var.get():
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
                    self.last_discovered_var = last_url
                    self.discovered_var.set(discovered_total)
                    self.inqueue_var.set(inqueue)
                    if getattr(self, "queue_auto_var", None) and self.queue_auto_var.get():
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
                    if getattr(self, "queue_auto_var", None) and self.queue_auto_var.get():
                        self.refresh_queue_view()
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

    # ---------- Log helpers ----------
    def _append_log_history(self, text, is_nonhtml=False, is_user=False):
        self._log_history.append((text, is_nonhtml, is_user))
        if len(self._log_history) > 20000: self._log_history.pop(0)

    def _apply_log_filter(self):
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
                if tags: self.text_box.insert(tk.END, text + "\n", tags)
                else: self.text_box.insert(tk.END, text + "\n")
        self.text_box.see(tk.END); self.text_box.config(state=tk.DISABLED)

# ---------- run ----------
if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    try: style.theme_use("clam")
    except Exception: pass
    app = CrawlerApp(root)
    root.mainloop()
