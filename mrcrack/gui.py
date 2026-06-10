"""
Mr.Crack GUI — brute-force password-protected archives using a wordlist.

Links to Mr.Pass:
  • Reads ~/Documents/MrPass/wordlist.txt by default
  • "Launch Mr.Pass" button opens the generator so you can build a tailored list
  • "Re-scan wordlist" refreshes the count without restarting

Supports: ZIP (built-in) · RAR (pip install rarfile) · 7-Zip (pip install py7zr)
"""
from __future__ import annotations
import os
import pathlib
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .cracker import crack_archive

# ── Paths ──────────────────────────────────────────────────────────────────────
_MRPASS_WORDLIST = pathlib.Path.home() / "Documents" / "MrPass" / "wordlist.txt"
_MRPASS_MAIN     = pathlib.Path(__file__).parent.parent.parent / "pwgen" / "main.py"

# ── Fonts / colours ────────────────────────────────────────────────────────────
_FONT    = ("Consolas", 10)
_FONT_H  = ("Consolas", 11, "bold")
_FONT_SM = ("Consolas", 9)
_FONT_BIG = ("Consolas", 20, "bold")

DARK: dict[str, str] = {
    "bg":       "#1e1e2e",
    "fg":       "#cdd6f4",
    "accent":   "#89b4fa",
    "btn_run":  "#a6e3a1",
    "btn_stop": "#f38ba8",
    "btn_fg":   "#1e1e2e",
    "entry_bg": "#313244",
    "log_bg":   "#11111b",
    "muted":    "#6c7086",
    "warn":     "#f9e2af",
    "sel_bg":   "#45475a",
    "found_bg": "#1a2e1a",
    "found_fg": "#a6e3a1",
}

LIGHT: dict[str, str] = {
    "bg":       "#f5f0ff",
    "fg":       "#2d1b6e",
    "accent":   "#7c3aed",
    "btn_run":  "#059669",
    "btn_stop": "#dc2626",
    "btn_fg":   "#ffffff",
    "entry_bg": "#ffffff",
    "log_bg":   "#ede9fe",
    "muted":    "#8b5cf6",
    "warn":     "#d97706",
    "sel_bg":   "#ddd6fe",
    "found_bg": "#ecfdf5",
    "found_fg": "#065f46",
}


class _Tip:
    def __init__(self, w: tk.Widget, text: str) -> None:
        self._w = w; self._text = text; self._top = None
        w.bind("<Enter>", self._show); w.bind("<Leave>", self._hide)

    def _show(self, _=None):
        if self._top: return
        x = self._w.winfo_rootx() + 12
        y = self._w.winfo_rooty() + self._w.winfo_height() + 4
        self._top = top = tk.Toplevel(self._w)
        top.wm_overrideredirect(True); top.wm_geometry(f"+{x}+{y}")
        tk.Label(top, text=self._text, justify="left",
                 bg="#313244", fg="#cdd6f4", font=("Consolas", 9),
                 relief="flat", padx=8, pady=5, wraplength=340).pack()

    def _hide(self, _=None):
        if self._top: self._top.destroy(); self._top = None


class MrCrackGUI:

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Mr.Crack — Archive Password Cracker")
        self.root.resizable(True, True)
        self.root.minsize(760, 680)

        self._dark_mode = True
        self.t = DARK.copy()
        self._stop_flag = threading.Event()
        self._running   = False
        self._log_q: queue.Queue = queue.Queue()

        self._rframes:  list[tk.Frame]       = []
        self._rlabels:  list[tuple]          = []
        self._rentries: list[tk.Entry]       = []
        self._rlframes: list[tuple]          = []
        self._rbtns_n:  list[tk.Button]      = []
        self._rtexts:   list[tuple]          = []

        self._build_ui()
        self._apply_ttk_style()
        self._poll_log()
        self._refresh_wordlist_count()

    # ── Registry helpers ───────────────────────────────────────────────────────

    def _rl(self, w, fg="fg"):  self._rlabels.append((w, fg)); return w
    def _rf(self, w):           self._rframes.append(w);       return w
    def _re(self, w):           self._rentries.append(w);      return w
    def _rlf(self, w, bg="bg"): self._rlframes.append((w,bg)); return w
    def _rbn(self, w):          self._rbtns_n.append(w);       return w
    def _rt(self, w, bg="log_bg"): self._rtexts.append((w,bg)); return w

    # ── Build UI ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        t = self.t

        # Title bar
        top = self._rf(tk.Frame(self.root, bg=t["bg"]))
        top.pack(fill="x", padx=10, pady=(8, 2))

        self._rl(tk.Label(top,
            text="Mr.Crack  •  Archive Password Cracker",
            font=("Consolas", 14, "bold"), bg=t["bg"], fg=t["accent"],
        ), "accent").pack(side="left")

        self.theme_btn = self._rbn(tk.Button(top, text="☀  Light mode",
            command=self._toggle_theme, bg=t["entry_bg"], fg=t["fg"],
            font=_FONT, relief="flat", padx=10, pady=3, cursor="hand2",
            activebackground=t["accent"], activeforeground=t["bg"],
        ))
        self.theme_btn.pack(side="right")

        self._rl(tk.Label(self.root,
            text="⚠  FOR AUTHORIZED SECURITY TESTING, CTF & PENTESTING ONLY",
            font=("Consolas", 9, "bold"), bg=t["bg"], fg=t["btn_stop"],
        ), "btn_stop").pack(fill="x", padx=10)

        ttk.Separator(self.root, orient="horizontal").pack(fill="x", pady=6)

        # ── Archive file picker ────────────────────────────────────────────────
        af = self._rlf(tk.LabelFrame(self.root,
            text=" 🗜  Target Archive ", font=_FONT_H,
            bg=t["bg"], fg=t["accent"], bd=1, relief="groove",
        ))
        af.pack(fill="x", padx=10, pady=(0, 4))

        self._rl(tk.Label(af, text="Archive file", bg=t["bg"], fg=t["fg"], font=_FONT)
             ).grid(row=0, column=0, sticky="e", padx=(8,4), pady=8)
        self.archive_var = tk.StringVar()
        archive_entry = self._re(tk.Entry(af, textvariable=self.archive_var, width=52,
            bg=t["entry_bg"], fg=t["fg"], insertbackground=t["fg"], font=_FONT))
        archive_entry.grid(row=0, column=1, padx=4, pady=8, sticky="ew")
        af.columnconfigure(1, weight=1)
        self._rbn(tk.Button(af, text="Browse…", command=self._browse_archive,
            bg=t["entry_bg"], fg=t["fg"], font=_FONT, cursor="hand2",
            activebackground=t["accent"], activeforeground=t["bg"],
        )).grid(row=0, column=2, padx=(4,8), pady=8)
        _Tip(archive_entry, "Path to a password-protected .zip, .rar, or .7z file.")

        self.archive_info = self._rl(tk.Label(af,
            text="Supported formats: .zip  .rar  .7z",
            bg=t["bg"], fg=t["muted"], font=_FONT_SM,
        ), "muted")
        self.archive_info.grid(row=1, column=0, columnspan=3, sticky="w", padx=(8,4), pady=(0,6))

        # ── Wordlist picker (links to Mr.Pass) ────────────────────────────────
        wf = self._rlf(tk.LabelFrame(self.root,
            text=" 📋  Wordlist  (from Mr.Pass) ", font=_FONT_H,
            bg=t["bg"], fg=t["accent"], bd=1, relief="groove",
        ))
        wf.pack(fill="x", padx=10, pady=4)

        self._rl(tk.Label(wf, text="Wordlist file", bg=t["bg"], fg=t["fg"], font=_FONT)
             ).grid(row=0, column=0, sticky="e", padx=(8,4), pady=8)
        self.wordlist_var = tk.StringVar(value=str(_MRPASS_WORDLIST))
        wl_entry = self._re(tk.Entry(wf, textvariable=self.wordlist_var, width=52,
            bg=t["entry_bg"], fg=t["fg"], insertbackground=t["fg"], font=_FONT))
        wl_entry.grid(row=0, column=1, padx=4, pady=8, sticky="ew")
        wf.columnconfigure(1, weight=1)

        btn_row = self._rf(tk.Frame(wf, bg=t["bg"]))
        btn_row.grid(row=0, column=2, padx=(4,8))

        self._rbn(tk.Button(btn_row, text="Browse…", command=self._browse_wordlist,
            bg=t["entry_bg"], fg=t["fg"], font=_FONT, cursor="hand2",
            activebackground=t["accent"], activeforeground=t["bg"],
        )).pack(side="left", padx=(0,4))

        self._rbn(tk.Button(btn_row, text="🔄 Rescan", command=self._refresh_wordlist_count,
            bg=t["entry_bg"], fg=t["fg"], font=_FONT, cursor="hand2",
            activebackground=t["accent"], activeforeground=t["bg"],
        )).pack(side="left", padx=(0,4))

        self.mrpass_btn = tk.Button(btn_row, text="⚡ Launch Mr.Pass",
            command=self._launch_mrpass, cursor="hand2",
            bg=t["accent"], fg=t["btn_fg"], font=_FONT,
            activebackground=t["btn_run"], activeforeground=t["btn_fg"],
        )
        self.mrpass_btn.pack(side="left")
        _Tip(self.mrpass_btn, "Open Mr.Pass to generate a tailored wordlist,\nthen come back and click Rescan.")

        self.wordlist_info = self._rl(tk.Label(wf,
            text="Checking wordlist…",
            bg=t["bg"], fg=t["muted"], font=_FONT_SM,
        ), "muted")
        self.wordlist_info.grid(row=1, column=0, columnspan=3, sticky="w", padx=(8,4), pady=(0,6))

        # ── Found password banner (hidden until cracked) ───────────────────────
        self.found_frame = tk.Frame(self.root, bg=t["found_bg"], pady=6)
        # packed dynamically when found

        self._rl(tk.Label(self.found_frame,
            text="🔓  PASSWORD FOUND", font=("Consolas", 10, "bold"),
            bg=t["found_bg"], fg=t["found_fg"],
        ), "found_fg").pack()

        self.found_pw_label = self._rl(tk.Label(self.found_frame,
            text="", font=_FONT_BIG,
            bg=t["found_bg"], fg=t["found_fg"],
        ), "found_fg")
        self.found_pw_label.pack(pady=(0, 4))

        self.copy_btn = self._rbn(tk.Button(self.found_frame,
            text="📋 Copy password", command=self._copy_password,
            bg=t["entry_bg"], fg=t["fg"], font=_FONT,
            relief="flat", padx=12, pady=4, cursor="hand2",
        ))
        self.copy_btn.pack()

        # ── Action buttons ─────────────────────────────────────────────────────
        bf = self._rf(tk.Frame(self.root, bg=t["bg"]))
        bf.pack(fill="x", padx=10, pady=6)

        self.run_btn = tk.Button(bf, text="🔓  Start Cracking",
            command=self._start_crack,
            bg=t["btn_run"], fg=t["btn_fg"], activebackground=t["btn_run"],
            font=("Consolas", 11, "bold"), width=18,
        )
        self.run_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = tk.Button(bf, text="■  Stop",
            command=self._stop_crack,
            bg=t["btn_stop"], fg=t["btn_fg"], activebackground=t["btn_stop"],
            font=("Consolas", 11, "bold"), width=10, state="disabled",
        )
        self.stop_btn.pack(side="left", padx=(0, 20))

        self.stats_label = self._rl(
            tk.Label(bf, text="", bg=t["bg"], fg=t["accent"], font=_FONT), "accent"
        )
        self.stats_label.pack(side="left", fill="x", expand=True)

        # Progress
        pf = self._rf(tk.Frame(self.root, bg=t["bg"]))
        pf.pack(fill="x", padx=10, pady=2)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(pf, variable=self.progress_var,
                                            mode="determinate", maximum=100)
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=(0,8))
        self.pct_label = self._rl(
            tk.Label(pf, text="", bg=t["bg"], fg=t["fg"], font=_FONT, width=20)
        )
        self.pct_label.pack(side="left")

        # Log
        self.log_box = scrolledtext.ScrolledText(self.root,
            bg=t["log_bg"], fg=t["fg"], font=_FONT,
            state="disabled", wrap="word", height=10,
        )
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(4, 8))
        self._rt(self.log_box, "log_bg")
        self._refresh_log_tags()

        # Welcome
        self.log_box.configure(state="normal")
        self.log_box.insert("end", "[INFO] Mr.Crack ready.\n", "INFO")
        self.log_box.insert("end", f"[INFO] Default wordlist: {_MRPASS_WORDLIST}\n", "INFO")
        self.log_box.insert("end", "[INFO] Select an archive, pick a wordlist, click Start Cracking.\n", "INFO")
        self.log_box.configure(state="disabled")

    # ── Theme ──────────────────────────────────────────────────────────────────

    def _toggle_theme(self) -> None:
        self._dark_mode = not self._dark_mode
        self.t = DARK.copy() if self._dark_mode else LIGHT.copy()
        self._apply_theme()
        self._apply_ttk_style()
        self.theme_btn.configure(
            text="☀  Light mode" if self._dark_mode else "☾  Dark mode"
        )

    def _apply_theme(self) -> None:
        t = self.t
        self.root.configure(bg=t["bg"])
        for w in self._rframes:
            try: w.configure(bg=t["bg"])
            except tk.TclError: pass
        for w, fg_key in self._rlabels:
            try: w.configure(fg=t[fg_key])
            except tk.TclError: pass
        for w in self._rentries:
            try: w.configure(bg=t["entry_bg"], fg=t["fg"], insertbackground=t["fg"])
            except tk.TclError: pass
        for w, bg_key in self._rlframes:
            try: w.configure(bg=t[bg_key], fg=t["accent"])
            except tk.TclError: pass
        for w in self._rbtns_n:
            try: w.configure(bg=t["entry_bg"], fg=t["fg"],
                              activebackground=t["accent"], activeforeground=t["bg"])
            except tk.TclError: pass
        for w, bg_key in self._rtexts:
            try: w.configure(bg=t[bg_key], fg=t["fg"], insertbackground=t["fg"])
            except tk.TclError: pass
        # Special buttons
        try:
            self.run_btn.configure(bg=t["btn_run"],  fg=t["btn_fg"])
            self.stop_btn.configure(bg=t["btn_stop"], fg=t["btn_fg"])
            self.mrpass_btn.configure(bg=t["accent"], fg=t["btn_fg"])
            self.found_frame.configure(bg=t["found_bg"])
            self.found_pw_label.configure(bg=t["found_bg"], fg=t["found_fg"])
            self.copy_btn.configure(bg=t["entry_bg"], fg=t["fg"])
        except (tk.TclError, AttributeError): pass
        self._refresh_log_tags()

    def _refresh_log_tags(self) -> None:
        t = self.t
        try:
            self.log_box.tag_config("INFO",    foreground=t["fg"])
            self.log_box.tag_config("OK",      foreground=t["btn_run"])
            self.log_box.tag_config("WARN",    foreground=t["warn"])
            self.log_box.tag_config("ERROR",   foreground=t["btn_stop"])
            self.log_box.tag_config("HEADING", foreground=t["accent"])
        except (tk.TclError, AttributeError): pass

    def _apply_ttk_style(self) -> None:
        t = self.t
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure("Horizontal.TProgressbar",
                    troughcolor=t["entry_bg"], background=t["accent"], thickness=16)
        s.configure("TSeparator", background=t["muted"])

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "INFO") -> None:
        self._log_q.put((level, msg))

    def _poll_log(self) -> None:
        while not self._log_q.empty():
            level, msg = self._log_q.get_nowait()
            self.log_box.configure(state="normal")
            self.log_box.insert("end", f"[{level}] {msg}\n", level)
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
        self.root.after(100, self._poll_log)

    def _browse_archive(self) -> None:
        path = filedialog.askopenfilename(
            title="Select password-protected archive",
            filetypes=[
                ("Archives", "*.zip *.rar *.7z"),
                ("ZIP",  "*.zip"),
                ("RAR",  "*.rar"),
                ("7-Zip","*.7z"),
                ("All",  "*.*"),
            ],
        )
        if path:
            self.archive_var.set(path)
            ext = pathlib.Path(path).suffix.lower()
            size_mb = pathlib.Path(path).stat().st_size / 1_048_576
            self.archive_info.configure(
                text=f"Selected: {pathlib.Path(path).name}  ({size_mb:.1f} MB)  [{ext}]"
            )

    def _browse_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Select wordlist",
            filetypes=[("Text", "*.txt"), ("All", "*.*")],
            initialdir=str(_MRPASS_WORDLIST.parent),
        )
        if path:
            self.wordlist_var.set(path)
            self._refresh_wordlist_count()

    def _refresh_wordlist_count(self) -> None:
        path = self.wordlist_var.get().strip()
        if not path or not pathlib.Path(path).exists():
            self.wordlist_info.configure(
                text=f"⚠  Wordlist not found: {path or '(none set)'}  —  Launch Mr.Pass to generate one."
            )
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                count = sum(1 for ln in fh if ln.strip() and not ln.startswith("#"))
            size_kb = pathlib.Path(path).stat().st_size / 1024
            self.wordlist_info.configure(
                text=f"✓  {count:,} passwords  |  {size_kb:.1f} KB  |  {pathlib.Path(path).name}"
            )
        except Exception as exc:
            self.wordlist_info.configure(text=f"Error reading wordlist: {exc}")

    def _launch_mrpass(self) -> None:
        """Launch the Mr.Pass GUI in a separate process."""
        try:
            # Try finding main.py relative to this project
            candidates = [
                _MRPASS_MAIN,
                pathlib.Path(__file__).parent.parent.parent / "pwgen" / "main.py",
                pathlib.Path.home() / "Documents" / "GitHub" / "pwgen" / "main.py",
            ]
            for p in candidates:
                if p.exists():
                    subprocess.Popen([sys.executable, str(p)])
                    self._log("Launched Mr.Pass — generate your wordlist, then click Rescan.", "OK")
                    return
            # Fallback: try as installed package
            subprocess.Popen([sys.executable, "-m", "pwgen"])
            self._log("Launched Mr.Pass via python -m pwgen.", "OK")
        except Exception as exc:
            messagebox.showwarning(
                "Cannot Launch Mr.Pass",
                f"Could not start Mr.Pass automatically:\n{exc}\n\n"
                f"Please open Mr.Pass manually, generate a wordlist,\n"
                f"then click Rescan."
            )

    def _copy_password(self) -> None:
        pw = self.found_pw_label.cget("text")
        if pw:
            self.root.clipboard_clear()
            self.root.clipboard_append(pw)
            self._log(f"Password copied to clipboard: {pw}", "OK")

    # ── Cracking ───────────────────────────────────────────────────────────────

    def _start_crack(self) -> None:
        if self._running: return

        archive  = self.archive_var.get().strip()
        wordlist = self.wordlist_var.get().strip()

        if not archive:
            messagebox.showerror("Mr.Crack", "Please select an archive file first.")
            return
        if not pathlib.Path(archive).exists():
            messagebox.showerror("Mr.Crack", f"Archive not found:\n{archive}")
            return
        if not wordlist or not pathlib.Path(wordlist).exists():
            messagebox.showerror(
                "Mr.Crack",
                f"Wordlist not found:\n{wordlist or '(none)'}\n\n"
                "Click 'Launch Mr.Pass' to generate one."
            )
            return

        # Hide any previous found banner
        try: self.found_frame.pack_forget()
        except Exception: pass

        self._stop_flag.clear()
        self._running = True
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.stats_label.configure(text="")
        self.progress_var.set(0)
        self.pct_label.configure(text="Starting…")

        self._log("─" * 44, "HEADING")
        self._log(f"Archive:  {archive}")
        self._log(f"Wordlist: {wordlist}")

        threading.Thread(
            target=self._crack_thread, args=(archive, wordlist), daemon=True
        ).start()

    def _stop_crack(self) -> None:
        self._stop_flag.set()
        self._log("Stop requested…", "WARN")

    def _crack_thread(self, archive: str, wordlist: str) -> None:
        try:
            found_pw: str | None = None
            tried = 0
            total = 0

            for tried, total, result in crack_archive(archive, wordlist, self._stop_flag):
                if result is not None:
                    found_pw = result
                    break

                if total > 0:
                    pct = (tried / total) * 100
                    self.root.after(0, lambda p=pct, tr=tried, to=total: (
                        self.progress_var.set(p),
                        self.pct_label.configure(
                            text=f"{tr:,} / {to:,}  ({p:.1f}%)"
                        ),
                        self.stats_label.configure(text=f"Tried: {tr:,}  |  Remaining: {to-tr:,}"),
                    ))

                if tried % 500 == 0 and tried > 0:
                    self._log(f"  … {tried:,} tried", "INFO")

            # Done
            if found_pw is not None:
                self._log(f"PASSWORD FOUND: {found_pw}", "OK")
                self._log(f"Archive: {archive}", "OK")
                self.root.after(0, lambda: self._show_found(found_pw, archive))
            elif self._stop_flag.is_set():
                self._log("Stopped — password not found yet.", "WARN")
                self.root.after(0, lambda: self.stats_label.configure(
                    text=f"Stopped at {tried:,} / {total:,}"))
            else:
                self._log(
                    f"Password NOT found in {tried:,} candidates.\n"
                    "  → Try generating a bigger wordlist with Mr.Pass\n"
                    "  → Add more seed words or use 'aggressive' mutations",
                    "WARN"
                )
                self.root.after(0, lambda: self.stats_label.configure(
                    text=f"Not found — {tried:,} tried"))

        except ValueError as exc:
            self._log(f"Error: {exc}", "ERROR")
        except Exception as exc:
            self._log(f"Unexpected error: {exc}", "ERROR")
        finally:
            self._running = False
            self.root.after(0, self._on_done)

    def _show_found(self, password: str, archive: str) -> None:
        self.found_pw_label.configure(text=password)
        self.found_frame.pack(fill="x", padx=10, pady=4)
        self.progress_var.set(100)
        self.pct_label.configure(text="CRACKED ✓")
        self.stats_label.configure(text=f"Found: {password}")

        # Save result next to wordlist
        result_path = pathlib.Path(self.wordlist_var.get()).parent / "cracked_result.txt"
        try:
            with open(result_path, "a", encoding="utf-8") as f:
                import datetime
                f.write(
                    f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  "
                    f"Archive: {archive}  |  Password: {password}\n"
                )
            self._log(f"Result saved → {result_path}", "OK")
        except Exception:
            pass

    def _on_done(self) -> None:
        self.run_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")


# ── Entry point ────────────────────────────────────────────────────────────────

def run_gui() -> None:
    root = tk.Tk()
    MrCrackGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
