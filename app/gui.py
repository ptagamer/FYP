import contextlib
import os
from pathlib import Path
import queue
import sqlite3
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import customtkinter as ctk
from PIL import Image, ImageTk

# Set global CustomTkinter appearance and theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# --- THE BRIDGES (Imports) ---
try:
    from .auth import Authenticator
    from .main import DATASET_FILE, run_detection_pipeline, train_detection_model
except ImportError:
    from auth import Authenticator
    from main import DATASET_FILE, run_detection_pipeline, train_detection_model

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.create_demo_files import DATA_DIR, create_demo_samples

DB_FILE = PROJECT_ROOT / "behavioral_security.db"
CHART_FILE = PROJECT_ROOT / "models" / "behavioral_feature_importance.png"
TRAINING_REPORT_FILE = PROJECT_ROOT / "models" / "latest_training_report.txt"
FAILED_TRAINING_REPORT_FILE = PROJECT_ROOT / "models" / "latest_failed_training_report.txt"


def center_window(window, width, height):
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x_position = max(0, (screen_width - width) // 2)
    y_position = max(0, (screen_height - height) // 2)
    window.geometry(f"{width}x{height}+{x_position}+{y_position}")


class QueueWriter:
    """File-like writer that sends training output safely back to the Tkinter thread."""
    def __init__(self, output_queue, report_parts):
        self.output_queue = output_queue
        self.report_parts = report_parts

    def write(self, text):
        if text:
            self.report_parts.append(text)
            self.output_queue.put(("output", text))

    def flush(self):
        pass


class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Behavioral Threat Defense // Security Portal")
        center_window(self.root, 420, 480)
        self.root.resizable(False, False)
        self.auth = Authenticator(DB_FILE)

        # Main container card
        card = ctk.CTkFrame(self.root, corner_radius=16, fg_color=("#F1F5F9", "#1E293B"))
        card.pack(fill="both", expand=True, padx=24, pady=24)

        # Header Badge & Icon
        badge = ctk.CTkLabel(
            card,
            text="🛡️ BEHAVIORAL THREAT DEFENSE",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=("#0284C7", "#38BDF8"),
        )
        badge.pack(pady=(28, 4))


        subtitle = ctk.CTkLabel(
            card,
            text="Behavioral Threat Intelligence & ML Triage",
            font=ctk.CTkFont(size=12),
            text_color=("#64748B", "#94A3B8"),
        )
        subtitle.pack(pady=(0, 24))

        # Form Fields
        fields_frame = ctk.CTkFrame(card, fg_color="transparent")
        fields_frame.pack(fill="x", padx=28)

        ctk.CTkLabel(
            fields_frame,
            text="OPERATOR USERNAME",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#475569", "#94A3B8"),
        ).pack(anchor="w", pady=(0, 4))

        self.user_entry = ctk.CTkEntry(
            fields_frame,
            placeholder_text="e.g. admin or analyst1",
            height=40,
            corner_radius=8,
        )
        self.user_entry.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            fields_frame,
            text="PASSWORD",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#475569", "#94A3B8"),
        ).pack(anchor="w", pady=(0, 4))

        self.pass_entry = ctk.CTkEntry(
            fields_frame,
            placeholder_text="Enter your password",
            show="*",
            height=40,
            corner_radius=8,
        )
        self.pass_entry.pack(fill="x", pady=(0, 22))

        # Action Button
        self.login_btn = ctk.CTkButton(
            fields_frame,
            text="Authenticate & Enter Console",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=42,
            corner_radius=8,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.handle_login,
        )
        self.login_btn.pack(fill="x", pady=(0, 12))

        # Enter key triggers login
        self.root.bind("<Return>", lambda event: self.handle_login())

        # Security footer
        ctk.CTkLabel(
            card,
            text="Role-Based Access Control • Active Forensic Audit Trail",
            font=ctk.CTkFont(size=10),
            text_color=("#94A3B8", "#64748B"),
        ).pack(side="bottom", pady=14)

    def handle_login(self):
        user = self.user_entry.get().strip()
        password = self.pass_entry.get()

        if not user or not password:
            messagebox.showwarning("Incomplete Credentials", "Please enter both username and password.")
            return

        user_role = self.auth.verify_credentials(user, password)

        if user_role:
            self.root.destroy()
            open_dashboard(user, user_role)
        else:
            messagebox.showerror("Access Denied", "Invalid username or password.")


class DetectionGUI:
    def __init__(self, root, username, role):
        self.root = root
        self.username = username
        self.role = role
        self.root.title(f"Behavioral Threat Analysis Console [{role.upper()}]")
        center_window(self.root, 1180, 760)
        self.root.minsize(1040, 680)

        self.auth = Authenticator(DB_FILE)
        self.selected_file = None
        self.training_thread = None

        # Build Main Responsive Layout: Sidebar (Col 0) + Workspace (Col 1)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_workspace()

        # Show initial view (Analysis & Triage)
        self.show_view("analysis")

    # ──────────────────────────────────────────────────────────────────────────
    # SIDEBAR NAVIGATION
    # ──────────────────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self.root, width=250, corner_radius=0, fg_color=("#0F172A", "#0B1120"))
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Brand / Logo
        logo_label = ctk.CTkLabel(
            self.sidebar,
            text="🛡️ THREAT DEFENSE",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#38BDF8",
        )
        logo_label.pack(anchor="w", padx=20, pady=(24, 2))

        sub_logo = ctk.CTkLabel(
            self.sidebar,
            text="Dynamic API Behavioral Classifier",
            font=ctk.CTkFont(size=11),
            text_color="#64748B",
        )
        sub_logo.pack(anchor="w", padx=20, pady=(0, 18))

        # User Profile Badge Card
        user_card = ctk.CTkFrame(self.sidebar, corner_radius=10, fg_color=("#1E293B", "#1E293B"))
        user_card.pack(fill="x", padx=16, pady=(0, 20))

        ctk.CTkLabel(
            user_card,
            text=f"👤 {self.username}",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#F8FAFC",
        ).pack(anchor="w", padx=12, pady=(10, 2))

        role_color = "#A855F7" if self.role == "Admin" else "#38BDF8"
        ctk.CTkLabel(
            user_card,
            text=f"ROLE: {self.role.upper()}",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=role_color,
        ).pack(anchor="w", padx=12, pady=(0, 2))

        ctk.CTkLabel(
            user_card,
            text="🟢 Engine Status: ONLINE",
            font=ctk.CTkFont(size=10),
            text_color="#10B981",
        ).pack(anchor="w", padx=12, pady=(0, 10))

        # Nav Buttons Section
        ctk.CTkLabel(
            self.sidebar,
            text="NAVIGATION",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#475569",
        ).pack(anchor="w", padx=20, pady=(0, 6))

        self.nav_buttons = {}

        # 1. Threat Analysis (All Roles)
        self.nav_buttons["analysis"] = self._create_nav_button(
            "🔍  Threat Analysis", lambda: self.show_view("analysis")
        )

        # Admin Only Navigation
        if self.role == "Admin":
            ctk.CTkLabel(
                self.sidebar,
                text="ADMINISTRATION",
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="#475569",
            ).pack(anchor="w", padx=20, pady=(14, 6))

            self.nav_buttons["training"] = self._create_nav_button(
                "⚙️  Model Training", lambda: self.show_view("training")
            )
            self.nav_buttons["audit"] = self._create_nav_button(
                "📈  Audit & Global XAI", lambda: self.show_view("audit")
            )
            self.nav_buttons["analysts"] = self._create_nav_button(
                "👥  Manage Analysts", lambda: self.show_view("analysts")
            )
            self.nav_buttons["demo"] = self._create_nav_button(
                "🧪  Demo Generator", lambda: self.show_view("demo")
            )

        # Sidebar Footer: Theme Toggle & Logout
        footer_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer_frame.pack(side="bottom", fill="x", padx=16, pady=20)

        theme_switch = ctk.CTkSwitch(
            footer_frame,
            text="Dark Palette",
            command=self._toggle_theme,
            onvalue="dark",
            offvalue="light",
        )
        theme_switch.select()
        theme_switch.pack(anchor="w", pady=(0, 12))

        logout_btn = ctk.CTkButton(
            footer_frame,
            text="🚪  Logout & Exit",
            font=ctk.CTkFont(size=12),
            height=34,
            corner_radius=8,
            fg_color="#334155",
            hover_color="#475569",
            command=self.root.quit,
        )
        logout_btn.pack(fill="x")

    def _create_nav_button(self, text, command):
        btn = ctk.CTkButton(
            self.sidebar,
            text=text,
            anchor="w",
            font=ctk.CTkFont(size=13, weight="normal"),
            height=38,
            corner_radius=8,
            fg_color="transparent",
            text_color="#94A3B8",
            hover_color="#1E293B",
            command=command,
        )
        btn.pack(fill="x", padx=12, pady=2)
        return btn

    def _toggle_theme(self):
        current = ctk.get_appearance_mode()
        ctk.set_appearance_mode("light" if current == "Dark" else "dark")

    # ──────────────────────────────────────────────────────────────────────────
    # WORKSPACE VIEW SWITCHER
    # ──────────────────────────────────────────────────────────────────────────
    def _build_workspace(self):
        self.workspace = ctk.CTkFrame(self.root, corner_radius=0, fg_color=("#F8FAFC", "#0F172A"))
        self.workspace.grid(row=0, column=1, sticky="nsew")
        self.workspace.columnconfigure(0, weight=1)
        self.workspace.rowconfigure(0, weight=1)

        # Dictionary of view frames
        self.views = {}
        self.views["analysis"] = self._init_analysis_view()

        if self.role == "Admin":
            self.views["training"] = self._init_training_view()
            self.views["audit"] = self._init_audit_view()
            self.views["analysts"] = self._init_analysts_view()
            self.views["demo"] = self._init_demo_view()

    def show_view(self, view_name):
        for name, frame in self.views.items():
            frame.grid_forget()

        for name, btn in self.nav_buttons.items():
            if name == view_name:
                btn.configure(fg_color="#2563EB", text_color="#FFFFFF", font=ctk.CTkFont(size=13, weight="bold"))
            else:
                btn.configure(fg_color="transparent", text_color="#94A3B8", font=ctk.CTkFont(size=13, weight="normal"))

        if view_name in self.views:
            self.views[view_name].grid(row=0, column=0, sticky="nsew", padx=24, pady=24)

    # ──────────────────────────────────────────────────────────────────────────
    # VIEW 1: THREAT ANALYSIS & TRIAGE WORKSPACE
    # ──────────────────────────────────────────────────────────────────────────
    def _init_analysis_view(self):
        view = ctk.CTkFrame(self.workspace, fg_color="transparent")
        view.columnconfigure(0, weight=1)

        # Header
        header = ctk.CTkFrame(view, fg_color="transparent")
        header.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            header,
            text="Behavioral Sandbox Log Analysis",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=("#0F172A", "#F8FAFC"),
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="Inspect Speakeasy emulator JSON logs or numeric CSV sequences for malicious behavioral patterns.",
            font=ctk.CTkFont(size=13),
            text_color=("#64748B", "#94A3B8"),
        ).pack(anchor="w", pady=(2, 0))

        # Card 1: Ingestion / File Selector Card
        ingest_card = ctk.CTkFrame(view, corner_radius=12, fg_color=("#FFFFFF", "#1E293B"))
        ingest_card.pack(fill="x", pady=(0, 16), ipady=12)

        ctk.CTkLabel(
            ingest_card,
            text="LOG INGESTION SOURCE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#64748B",
        ).pack(anchor="w", padx=20, pady=(6, 4))

        selector_row = ctk.CTkFrame(ingest_card, fg_color="transparent")
        selector_row.pack(fill="x", padx=20, pady=(0, 8))
        selector_row.columnconfigure(0, weight=1)

        self.file_entry = ctk.CTkEntry(
            selector_row,
            placeholder_text="No behavioral log selected. Click 'Browse Log' to choose a .json or .csv sample...",
            height=40,
            state="readonly",
        )
        self.file_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        browse_btn = ctk.CTkButton(
            selector_row,
            text="📁 Browse Log",
            font=ctk.CTkFont(weight="bold"),
            height=40,
            width=130,
            command=self.select_file,
        )
        browse_btn.grid(row=0, column=1)

        action_row = ctk.CTkFrame(ingest_card, fg_color="transparent")
        action_row.pack(fill="x", padx=20)

        self.file_info_lbl = ctk.CTkLabel(
            action_row,
            text="Supported: Speakeasy JSON emulator reports, dynamic API CSV sequence logs.",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8",
        )
        self.file_info_lbl.pack(side="left")

        self.analyze_btn = ctk.CTkButton(
            action_row,
            text="⚡ Run Threat Analysis",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            width=180,
            fg_color="#0D9488",
            hover_color="#0F766E",
            command=self.execute_analysis,
        )
        self.analyze_btn.pack(side="right")

        # Card 2: Threat Triage Console Card
        self.result_card = ctk.CTkFrame(view, corner_radius=12, fg_color=("#FFFFFF", "#1E293B"))
        self.result_card.pack(fill="both", expand=True)

        # Placeholder inside Result Card
        self.placeholder_frame = ctk.CTkFrame(self.result_card, fg_color="transparent")
        self.placeholder_frame.pack(fill="both", expand=True, padx=20, pady=40)

        ctk.CTkLabel(
            self.placeholder_frame,
            text="🔬",
            font=ctk.CTkFont(size=48),
        ).pack(pady=(20, 10))

        ctk.CTkLabel(
            self.placeholder_frame,
            text="Ready for Behavioral Analysis",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=("#1E293B", "#F8FAFC"),
        ).pack()

        ctk.CTkLabel(
            self.placeholder_frame,
            text="Select a behavioral log file above and trigger 'Run Threat Analysis' to generate triage telemetry.",
            font=ctk.CTkFont(size=13),
            text_color="#94A3B8",
        ).pack(pady=(4, 20))

        # Active Result Frame (hidden initially)
        self.active_result_frame = ctk.CTkFrame(self.result_card, fg_color="transparent")

        return view

    def select_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Supported Behavioral Datasets", "*.csv *.json"), ("All Files", "*.*")]
        )
        if file_path:
            self.selected_file = file_path
            self.file_entry.configure(state="normal")
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, file_path)
            self.file_entry.configure(state="readonly")

            size_kb = os.path.getsize(file_path) / 1024
            ext = Path(file_path).suffix.upper()
            self.file_info_lbl.configure(
                text=f"Ready: {Path(file_path).name}  |  Format: {ext}  |  Size: {size_kb:.1f} KB",
                text_color=("#0284C7", "#38BDF8"),
            )

    def execute_analysis(self):
        if not self.selected_file:
            messagebox.showwarning("Log Required", "Please select a behavioral log file first.")
            return

        try:
            self.analyze_btn.configure(state="disabled", text="Analyzing...")
            self.root.update_idletasks()

            self.auth.log_action(self.username, f"Ran analysis on {os.path.basename(self.selected_file)}")
            report = run_detection_pipeline(self.selected_file)

            verdict = report["verdict"]
            confidence = report["confidence"]
            threat_score = report.get("threat_score", confidence)
            severity = report.get("severity", "EVALUATED")
            severity_color = report.get("severity_color", "#EF4444" if verdict == "Malicious" else "#10B981")
            reason = report["reason"]
            mitre_techniques = report.get("mitre_techniques", [])
            api_timeline = report.get("api_timeline", [])
            total_calls = report.get("total_api_calls", len(api_timeline))
            unique_calls = report.get("unique_api_count", len(set(e.get("api") for e in api_timeline)))

            # Switch from placeholder to populated triage card
            self.placeholder_frame.pack_forget()
            self.active_result_frame.pack_forget()
            for widget in self.active_result_frame.winfo_children():
                widget.destroy()

            self.active_result_frame.pack(fill="both", expand=True, padx=16, pady=16)

            is_malicious = verdict == "Malicious"

            # ── TOP ROW: 3 KEY TELEMETRY CARDS ───────────────────────────────
            top_row = ctk.CTkFrame(self.active_result_frame, fg_color="transparent")
            top_row.pack(fill="x", pady=(0, 12))
            top_row.columnconfigure(0, weight=1)
            top_row.columnconfigure(1, weight=1)
            top_row.columnconfigure(2, weight=1)

            # Card 1: Threat Severity & Risk Meter (0 - 100)
            score_card = ctk.CTkFrame(
                top_row,
                corner_radius=10,
                fg_color=("#F8FAFC", "#0B1120"),
                border_width=2,
                border_color=severity_color,
            )
            score_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6), ipady=8)

            ctk.CTkLabel(
                score_card,
                text="THREAT SEVERITY SCORE",
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="#64748B",
            ).pack(anchor="w", padx=14, pady=(6, 2))

            score_row = ctk.CTkFrame(score_card, fg_color="transparent")
            score_row.pack(fill="x", padx=14)

            ctk.CTkLabel(
                score_row,
                text=f"{threat_score}",
                font=ctk.CTkFont(size=26, weight="bold"),
                text_color=severity_color,
            ).pack(side="left")

            ctk.CTkLabel(
                score_row,
                text="/ 100",
                font=ctk.CTkFont(size=13),
                text_color="#64748B",
            ).pack(side="left", padx=(3, 8), pady=(6, 0))

            badge_chip = ctk.CTkLabel(
                score_row,
                text=f" {severity} ",
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color=severity_color,
                text_color="#FFFFFF",
                corner_radius=6,
            )
            badge_chip.pack(side="right")

            score_bar = ctk.CTkProgressBar(score_card, height=8, corner_radius=4)
            score_bar.pack(fill="x", padx=14, pady=(6, 4))
            score_bar.set(min(1.0, max(0.0, threat_score / 100.0)))
            score_bar.configure(progress_color=severity_color)

            # Card 2: ML Classification Verdict
            verdict_card = ctk.CTkFrame(
                top_row,
                corner_radius=10,
                fg_color=("#F8FAFC", "#0B1120"),
            )
            verdict_card.grid(row=0, column=1, sticky="nsew", padx=6, ipady=8)

            ctk.CTkLabel(
                verdict_card,
                text="ML CLASSIFIER VERDICT",
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="#64748B",
            ).pack(anchor="w", padx=14, pady=(6, 2))

            ctk.CTkLabel(
                verdict_card,
                text=verdict.upper(),
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color="#EF4444" if is_malicious else "#10B981",
            ).pack(anchor="w", padx=14)

            ctk.CTkLabel(
                verdict_card,
                text=f"Confidence: {confidence:.2f}% (Balanced Random Forest)",
                font=ctk.CTkFont(size=11),
                text_color="#94A3B8",
            ).pack(anchor="w", padx=14, pady=(2, 4))

            conf_bar = ctk.CTkProgressBar(verdict_card, height=8, corner_radius=4)
            conf_bar.pack(fill="x", padx=14, pady=(4, 4))
            conf_bar.set(confidence / 100.0)
            conf_bar.configure(progress_color="#EF4444" if is_malicious else "#10B981")

            # Card 3: Artifact Telemetry
            meta_card = ctk.CTkFrame(
                top_row,
                corner_radius=10,
                fg_color=("#F8FAFC", "#0B1120"),
            )
            meta_card.grid(row=0, column=2, sticky="nsew", padx=(6, 0), ipady=8)

            ctk.CTkLabel(
                meta_card,
                text="ARTIFACT TELEMETRY",
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="#64748B",
            ).pack(anchor="w", padx=14, pady=(6, 2))

            sample_name = os.path.basename(self.selected_file)
            if len(sample_name) > 28:
                sample_name = sample_name[:25] + "..."
            ctk.CTkLabel(
                meta_card,
                text=sample_name,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=("#1E293B", "#F8FAFC"),
            ).pack(anchor="w", padx=14)

            ctk.CTkLabel(
                meta_card,
                text=f"• Sequence Traces: {total_calls} calls\n• Distinct API Types: {unique_calls}\n• Flagged ATT&CK® Behaviors: {len(mitre_techniques)}",
                font=ctk.CTkFont(size=11),
                text_color="#94A3B8",
                justify="left",
            ).pack(anchor="w", padx=14, pady=(2, 4))

            # ── BOTTOM SECTION: TABBED DRILL-DOWN WORKSPACE ───────────────────
            detail_tabs = ctk.CTkTabview(self.active_result_frame, corner_radius=10)
            detail_tabs.pack(fill="both", expand=True)

            tab_mitre = detail_tabs.add("🎯 MITRE ATT&CK® & Explainable AI")
            tab_timeline = detail_tabs.add("⏱️ Runtime API Execution Timeline")

            # --- TAB 1: MITRE ATT&CK® & XAI ---
            ctk.CTkLabel(
                tab_mitre,
                text="DETECTED ENTERPRISE ATT&CK® BEHAVIORS",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#38BDF8",
            ).pack(anchor="w", padx=14, pady=(8, 4))

            if mitre_techniques:
                mitre_scroll = ctk.CTkScrollableFrame(tab_mitre, height=130, corner_radius=8, fg_color=("#F1F5F9", "#0B1120"))
                mitre_scroll.pack(fill="x", padx=14, pady=(0, 10))

                for t in mitre_techniques:
                    t_card = ctk.CTkFrame(mitre_scroll, corner_radius=6, fg_color=("#E2E8F0", "#1E293B"))
                    t_card.pack(fill="x", pady=2, padx=4)

                    tag = ctk.CTkLabel(
                        t_card,
                        text=f" {t['id']} ",
                        font=ctk.CTkFont(size=10, weight="bold"),
                        fg_color=t.get('color', '#EF4444'),
                        text_color="#FFFFFF",
                        corner_radius=4,
                    )
                    tag.pack(side="left", padx=8, pady=4)

                    ctk.CTkLabel(
                        t_card,
                        text=f"{t['name']}",
                        font=ctk.CTkFont(size=11, weight="bold"),
                        text_color=("#0F172A", "#F8FAFC"),
                    ).pack(side="left", padx=(0, 10))

                    ctk.CTkLabel(
                        t_card,
                        text=f"[{t['tactic']}]",
                        font=ctk.CTkFont(size=10),
                        text_color="#64748B",
                    ).pack(side="left", padx=(0, 10))

                    ctk.CTkLabel(
                        t_card,
                        text=f"Trigger: {t['api']}",
                        font=ctk.CTkFont(size=10, weight="bold"),
                        text_color=("#475569", "#94A3B8"),
                    ).pack(side="right", padx=10)
            else:
                ctk.CTkLabel(
                    tab_mitre,
                    text="No high-risk enterprise ATT&CK® behavioral patterns detected in this execution sample.",
                    font=ctk.CTkFont(size=12),
                    text_color="#10B981",
                ).pack(anchor="w", padx=14, pady=(0, 10))

            # Forensic XAI Callout Box
            ctk.CTkLabel(
                tab_mitre,
                text="PRIMARY FORENSIC REASONING (LOCAL XAI)",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#38BDF8",
            ).pack(anchor="w", padx=14, pady=(4, 4))

            callout = ctk.CTkFrame(
                tab_mitre,
                corner_radius=8,
                fg_color=("#EDE9FE", "#1E1B4B") if is_malicious else ("#E0F2FE", "#082F49"),
            )
            callout.pack(fill="x", padx=14, pady=(0, 8))

            ctk.CTkLabel(
                callout,
                text=reason,
                font=ctk.CTkFont(size=12),
                text_color=("#581C87", "#DDD6FE") if is_malicious else ("#075985", "#BAE6FD"),
                wraplength=760,
                justify="left",
            ).pack(anchor="w", padx=12, pady=10)

            # --- TAB 2: RUNTIME API TIMELINE ---
            ctk.CTkLabel(
                tab_timeline,
                text="CHRONOLOGICAL API CALL SEQUENCE (SPEAKEASY EXECUTION TRACE)",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#38BDF8",
            ).pack(anchor="w", padx=14, pady=(8, 4))

            timeline_scroll = ctk.CTkScrollableFrame(tab_timeline, corner_radius=8, fg_color=("#F1F5F9", "#0B1120"))
            timeline_scroll.pack(fill="both", expand=True, padx=14, pady=(0, 8))

            if api_timeline:
                for idx, ev in enumerate(api_timeline):
                    row = ctk.CTkFrame(timeline_scroll, corner_radius=4, fg_color=("#E2E8F0", "#1E293B"))
                    row.pack(fill="x", pady=2, padx=4)

                    step_lbl = ctk.CTkLabel(
                        row,
                        text=f"#{idx+1:02d} ({ev['step']})",
                        font=ctk.CTkFont(size=10, family="Courier"),
                        text_color="#64748B",
                        width=70,
                    )
                    step_lbl.pack(side="left", padx=6, pady=3)

                    api_lbl = ctk.CTkLabel(
                        row,
                        text=ev['api'],
                        font=ctk.CTkFont(size=11, weight="bold"),
                        text_color=("#0F172A", "#F8FAFC"),
                        width=200,
                        anchor="w",
                    )
                    api_lbl.pack(side="left", padx=6)

                    if ev['mitre']:
                        m = ev['mitre']
                        m_chip = ctk.CTkLabel(
                            row,
                            text=f" {m['id']} {m['name']} ",
                            font=ctk.CTkFont(size=9, weight="bold"),
                            fg_color=m.get('color', '#EF4444'),
                            text_color="#FFFFFF",
                            corner_radius=4,
                        )
                        m_chip.pack(side="left", padx=6)

                    desc_lbl = ctk.CTkLabel(
                        row,
                        text=ev['description'],
                        font=ctk.CTkFont(size=10),
                        text_color="#94A3B8",
                        anchor="w",
                    )
                    desc_lbl.pack(side="left", padx=6, fill="x", expand=True)
            else:
                ctk.CTkLabel(
                    timeline_scroll,
                    text="No active API trace events observed in sequence.",
                    text_color="#94A3B8",
                ).pack(pady=20)

        except Exception as exc:
            messagebox.showerror("Analysis Error", f"Behavioral analysis failed:\n{exc}")
        finally:
            self.analyze_btn.configure(state="normal", text="⚡ Run Threat Analysis")

    # ──────────────────────────────────────────────────────────────────────────
    # VIEW 2: MODEL TRAINING WORKSPACE (Admin Only)
    # ──────────────────────────────────────────────────────────────────────────
    def _init_training_view(self):
        view = ctk.CTkFrame(self.workspace, fg_color="transparent")
        view.columnconfigure(0, weight=1)

        # Header
        ctk.CTkLabel(
            view,
            text="Model Training & Validation Engine",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(anchor="w")

        ctk.CTkLabel(
            view,
            text="Trains Random Forest and Linear SVM with 5-Fold Stratified Cross-Validation and in-fold SMOTE class balancing.",
            font=ctk.CTkFont(size=13),
            text_color="#94A3B8",
        ).pack(anchor="w", pady=(2, 16))

        # Dataset Select Card
        cfg_card = ctk.CTkFrame(view, corner_radius=12, fg_color=("#FFFFFF", "#1E293B"))
        cfg_card.pack(fill="x", pady=(0, 16), padx=0)

        cfg_row = ctk.CTkFrame(cfg_card, fg_color="transparent")
        cfg_row.pack(fill="x", padx=16, pady=12)
        cfg_row.columnconfigure(0, weight=1)

        self.training_file_var = tk.StringVar(value=str(DATASET_FILE))

        self.train_entry = ctk.CTkEntry(
            cfg_row,
            textvariable=self.training_file_var,
            state="readonly",
            height=38,
        )
        self.train_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        ctk.CTkButton(
            cfg_row,
            text="Browse CSV",
            width=110,
            height=38,
            command=self._select_training_csv,
        ).grid(row=0, column=1, padx=(0, 10))

        self.start_train_btn = ctk.CTkButton(
            cfg_row,
            text="🚀 Start Training Pipeline",
            font=ctk.CTkFont(weight="bold"),
            height=38,
            fg_color="#8B5CF6",
            hover_color="#7C3AED",
            command=self.start_training_pipeline,
        )
        self.start_train_btn.grid(row=0, column=2)

        # Live Console Output Card
        output_card = ctk.CTkFrame(view, corner_radius=12, fg_color=("#FFFFFF", "#1E293B"))
        output_card.pack(fill="both", expand=True)

        header_row = ctk.CTkFrame(output_card, fg_color="transparent")
        header_row.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            header_row,
            text="TRAINING TELEMETRY CONSOLE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#64748B",
        ).pack(side="left")

        self.train_status_lbl = ctk.CTkLabel(
            header_row,
            text="Idle. Ready to train.",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8",
        )
        self.train_status_lbl.pack(side="right")

        self.train_textbox = ctk.CTkTextbox(
            output_card,
            font=ctk.CTkFont(family="Courier", size=12),
            wrap="word",
        )
        self.train_textbox.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # Pre-load previous training report if present
        if TRAINING_REPORT_FILE.exists():
            try:
                self.train_textbox.insert("1.0", TRAINING_REPORT_FILE.read_text(encoding="utf-8"))
                self.train_status_lbl.configure(text=f"Loaded prior report: {TRAINING_REPORT_FILE.name}")
            except Exception:
                pass

        return view

    def _select_training_csv(self):
        file_path = filedialog.askopenfilename(
            initialdir=DATASET_FILE.parent,
            filetypes=[("CSV datasets", "*.csv")],
        )
        if file_path:
            self.training_file_var.set(file_path)

    def start_training_pipeline(self):
        if self.training_thread and self.training_thread.is_alive():
            messagebox.showinfo("In Progress", "Model training is currently running.")
            return

        training_path = Path(self.training_file_var.get())
        if not training_path.exists():
            messagebox.showerror("File Error", f"Training dataset not found:\n{training_path}")
            return

        output_queue = queue.Queue()
        self.train_textbox.delete("1.0", "end")
        self.train_status_lbl.configure(text="⚡ Training active. Please wait...", text_color="#38BDF8")
        self.start_train_btn.configure(state="disabled")

        self.auth.log_action(self.username, f"Started model training with {training_path.name}")

        self.training_thread = threading.Thread(
            target=self._run_training_worker,
            args=(output_queue, training_path),
            daemon=True,
        )
        self.training_thread.start()
        self.root.after(100, self._poll_training_queue, output_queue)

    def _run_training_worker(self, output_queue, training_path):
        report_parts = [f"Starting model training...\nDataset: {training_path}\n\n"]
        writer = QueueWriter(output_queue, report_parts)
        try:
            output_queue.put(("output", report_parts[0]))
            with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                train_detection_model(training_path)
            report_parts.append("\nModel training completed successfully.\n")
            TRAINING_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
            TRAINING_REPORT_FILE.write_text("".join(report_parts), encoding="utf-8")
            output_queue.put(("complete", "Model training completed successfully."))
        except Exception as exc:
            err = f"Model training failed: {exc}"
            report_parts.append(f"\n{err}\n")
            FAILED_TRAINING_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
            FAILED_TRAINING_REPORT_FILE.write_text("".join(report_parts), encoding="utf-8")
            output_queue.put(("error", err))

    def _poll_training_queue(self, output_queue):
        while True:
            try:
                msg_type, message = output_queue.get_nowait()
            except queue.Empty:
                break

            if msg_type == "output":
                self.train_textbox.insert("end", message)
                self.train_textbox.see("end")
            elif msg_type == "complete":
                self.train_textbox.insert("end", f"\n{message}\n")
                self.train_textbox.see("end")
                self.train_status_lbl.configure(text=message, text_color="#10B981")
                self.start_train_btn.configure(state="normal")
                self.auth.log_action(self.username, "Completed model training")
                messagebox.showinfo("Training Success", message)
                return
            elif msg_type == "error":
                self.train_textbox.insert("end", f"\n{message}\n")
                self.train_textbox.see("end")
                self.train_status_lbl.configure(text=message, text_color="#EF4444")
                self.start_train_btn.configure(state="normal")
                self.auth.log_action(self.username, message)
                messagebox.showerror("Training Error", message)
                return

        if self.training_thread and self.training_thread.is_alive():
            self.root.after(100, self._poll_training_queue, output_queue)

    # ──────────────────────────────────────────────────────────────────────────
    # VIEW 3: AUDIT TRAIL & GLOBAL XAI WORKSPACE (Admin Only)
    # ──────────────────────────────────────────────────────────────────────────
    def _init_audit_view(self):
        view = ctk.CTkFrame(self.workspace, fg_color="transparent")
        view.columnconfigure(0, weight=1)
        view.rowconfigure(1, weight=1)

        ctk.CTkLabel(
            view,
            text="Forensic Audit Trail & Global Explainability",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(anchor="w")

        ctk.CTkLabel(
            view,
            text="Immutable operator action trail and global Random Forest feature importance analytics.",
            font=ctk.CTkFont(size=13),
            text_color="#94A3B8",
        ).pack(anchor="w", pady=(2, 16))

        # Tabview for Audit Log vs Global Feature Importance
        tabview = ctk.CTkTabview(view, corner_radius=12)
        tabview.pack(fill="both", expand=True)

        tab_audit = tabview.add("📜 Forensic Audit Trail")
        tab_chart = tabview.add("📊 Global Model Feature Importance (XAI)")

        # Tab 1: Audit Log Table
        self.audit_textbox = ctk.CTkTextbox(
            tab_audit,
            font=ctk.CTkFont(family="Courier", size=12),
        )
        self.audit_textbox.pack(fill="both", expand=True, padx=12, pady=(12, 10))

        ctk.CTkButton(
            tab_audit,
            text="🔄 Refresh Audit Trail",
            width=160,
            command=self._refresh_audit_logs,
        ).pack(anchor="e", padx=12, pady=(0, 10))

        self._refresh_audit_logs()

        # Tab 2: Feature Importance Chart
        ctk.CTkLabel(
            tab_chart,
            text="Top 10 Most Influential Behavioral Indicators Across Training Set",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            tab_chart,
            text="Features t_0 to t_99 indicate sequence positions, decoded to human-readable API names. Engineered features represent behavioral entropy and variance.",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8",
            wraplength=760,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 12))

        self.chart_container = ctk.CTkLabel(tab_chart, text="")
        self.chart_container.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self._load_global_chart()

        return view

    def _refresh_audit_logs(self):
        self.audit_textbox.delete("1.0", "end")
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
                logs = cursor.fetchall()
                for log in logs:
                    self.audit_textbox.insert("end", f"[{log[3]}] [OPERATOR: {log[1]}] -> {log[2]}\n")
        except Exception as exc:
            self.audit_textbox.insert("end", f"Failed to query audit trail: {exc}")

    def _load_global_chart(self):
        if CHART_FILE.exists():
            try:
                img = Image.open(CHART_FILE)
                img = img.resize((740, 390), Image.Resampling.LANCZOS)
                self.chart_img = ctk.CTkImage(light_image=img, dark_image=img, size=(740, 390))
                self.chart_container.configure(image=self.chart_img, text="")
            except Exception as exc:
                self.chart_container.configure(text=f"Failed to render chart: {exc}")
        else:
            self.chart_container.configure(text="[Global XAI Chart not found. Run model training to generate chart.]")

    # ──────────────────────────────────────────────────────────────────────────
    # VIEW 4: ANALYST ACCOUNT MANAGEMENT (Admin Only)
    # ──────────────────────────────────────────────────────────────────────────
    def _init_analysts_view(self):
        view = ctk.CTkFrame(self.workspace, fg_color="transparent")
        view.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            view,
            text="Analyst Account Management",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(anchor="w")

        ctk.CTkLabel(
            view,
            text="Provision and audit credentialed Analyst roles with restricted access permissions.",
            font=ctk.CTkFont(size=13),
            text_color="#94A3B8",
        ).pack(anchor="w", pady=(2, 16))

        card = ctk.CTkFrame(view, corner_radius=12, fg_color=("#FFFFFF", "#1E293B"))
        card.pack(fill="both", expand=True)

        # Analyst list textbox / list
        self.analyst_box = ctk.CTkTextbox(
            card,
            font=ctk.CTkFont(family="Courier", size=13),
        )
        self.analyst_box.pack(fill="both", expand=True, padx=16, pady=16)

        # Action bar
        act_row = ctk.CTkFrame(card, fg_color="transparent")
        act_row.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkButton(
            act_row,
            text="➕ Create Analyst",
            command=self._create_analyst_flow,
            width=140,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            act_row,
            text="🔑 Reset Password",
            command=self._reset_analyst_flow,
            width=140,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            act_row,
            text="🗑️ Delete Analyst",
            command=self._delete_analyst_flow,
            fg_color="#EF4444",
            hover_color="#DC2626",
            width=140,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            act_row,
            text="🔄 Refresh",
            command=self._refresh_analysts_list,
            width=100,
        ).pack(side="right")

        self._refresh_analysts_list()
        return view

    def _refresh_analysts_list(self):
        self.analyst_box.delete("1.0", "end")
        analysts = self.auth.list_users(role="Analyst")
        self.analyst_box.insert("end", f"{'ID':<6} {'USERNAME':<30} {'ROLE':<15}\n")
        self.analyst_box.insert("end", "=" * 55 + "\n")
        for uid, uname, urole in analysts:
            self.analyst_box.insert("end", f"{uid:<6} {uname:<30} {urole:<15}\n")

    def _create_analyst_flow(self):
        username = simpledialog.askstring("Create Analyst", "Analyst Username:", parent=self.root)
        if not username:
            return
        password = simpledialog.askstring("Create Analyst", "Password:", show="*", parent=self.root)
        if not password:
            return

        try:
            created = self.auth.create_analyst(username, password)
            self.auth.log_action(self.username, f"Created analyst account '{created}'")
            self._refresh_analysts_list()
            messagebox.showinfo("Success", f"Created analyst account: {created}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _reset_analyst_flow(self):
        username = simpledialog.askstring("Reset Password", "Enter Username to Reset:", parent=self.root)
        if not username:
            return
        password = simpledialog.askstring("Reset Password", f"New Password for {username}:", show="*", parent=self.root)
        if not password:
            return

        try:
            self.auth.reset_analyst_password(username, password)
            self.auth.log_action(self.username, f"Reset password for analyst '{username}'")
            messagebox.showinfo("Success", f"Password reset for: {username}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _delete_analyst_flow(self):
        username = simpledialog.askstring("Delete Analyst", "Enter Username to Delete:", parent=self.root)
        if not username:
            return
        confirmed = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{username}'?")
        if not confirmed:
            return

        try:
            self.auth.delete_analyst(username)
            self.auth.log_action(self.username, f"Deleted analyst account '{username}'")
            self._refresh_analysts_list()
            messagebox.showinfo("Deleted", f"Deleted analyst account: {username}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    # ──────────────────────────────────────────────────────────────────────────
    # VIEW 5: SYNTHETIC DEMO GENERATOR (Admin Only)
    # ──────────────────────────────────────────────────────────────────────────
    def _init_demo_view(self):
        view = ctk.CTkFrame(self.workspace, fg_color="transparent")
        view.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            view,
            text="Synthetic Demo File Generator",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(anchor="w")

        ctk.CTkLabel(
            view,
            text="Extracts verified malicious (malware=1) and benign (malware=0) single-sample files for live evaluations.",
            font=ctk.CTkFont(size=13),
            text_color="#94A3B8",
        ).pack(anchor="w", pady=(2, 16))

        card = ctk.CTkFrame(view, corner_radius=12, fg_color=("#FFFFFF", "#1E293B"))
        card.pack(fill="x", pady=(0, 16))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=16)
        row.columnconfigure(0, weight=1)

        self.demo_source_var = tk.StringVar(value=str(DATA_DIR / "dynamic_api_call_sequence_per_malware_100_0_306.csv"))

        entry = ctk.CTkEntry(row, textvariable=self.demo_source_var, state="readonly", height=38)
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        def browse_demo_csv():
            path = filedialog.askopenfilename(initialdir=DATA_DIR, filetypes=[("CSV datasets", "*.csv")])
            if path:
                self.demo_source_var.set(path)

        ctk.CTkButton(row, text="Browse CSV", width=110, height=38, command=browse_demo_csv).grid(row=0, column=1, padx=(0, 10))

        def run_gen():
            src = self.demo_source_var.get()
            try:
                res = create_demo_samples(src)
                if res:
                    mal, ben = res
                    self.auth.log_action(self.username, f"Generated demo files from {Path(src).name}")
                    self.demo_status.configure(
                        text=f"✅ Created demo files:\n  • Malicious: {Path(mal).name}\n  • Benign: {Path(ben).name}",
                        text_color="#10B981",
                    )
                    messagebox.showinfo("Success", "Demo files successfully generated in data folder.")
            except Exception as exc:
                self.demo_status.configure(text=f"❌ Error: {exc}", text_color="#EF4444")
                messagebox.showerror("Error", str(exc))

        ctk.CTkButton(
            row,
            text="✨ Generate Demo Pair",
            font=ctk.CTkFont(weight="bold"),
            height=38,
            fg_color="#0D9488",
            hover_color="#0F766E",
            command=run_gen,
        ).grid(row=0, column=2)

        self.demo_status = ctk.CTkLabel(
            card,
            text="Ready to generate demo payload files.",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8",
            justify="left",
        )
        self.demo_status.pack(anchor="w", padx=16, pady=(0, 16))

        return view


def open_dashboard(username, role):
    main_root = ctk.CTk()
    DetectionGUI(main_root, username, role)
    main_root.mainloop()


if __name__ == "__main__":
    login_root = ctk.CTk()
    LoginWindow(login_root)
    login_root.mainloop()
