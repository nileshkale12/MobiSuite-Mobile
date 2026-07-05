import os
import subprocess
import threading
import zipfile
import shutil
import sys
import urllib.request
import urllib.parse
import importlib.util
import time
import re
import xml.etree.ElementTree as ET
import hashlib
import lzma

print("[*] Starting script initialization...")

# ---------------------------------------------------------------------
# CROSS-PLATFORM PLATFORM CONFIGURATION LAYER
# ---------------------------------------------------------------------
IS_LINUX = sys.platform.startswith("linux")
KALI_FLAG = ["--break-system-packages"] if IS_LINUX else []
SUBPROCESS_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    import customtkinter as ctk
    print("[+] CustomTkinter GUI engine mapped successfully.")
except ImportError:
    print("[*] Installing CustomTkinter modern UI framework wrapper...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"] + KALI_FLAG)
        import customtkinter as ctk
        from tkinter import filedialog, messagebox
    except Exception as e:
        print(f"[-] CRITICAL ERROR: Framework setup aborted: {e}")
        sys.exit(1)

try:
    import paramiko
    from scp import SCPClient
    print("[+] Paramiko and SCP modules imported successfully.")
except ImportError:
    paramiko = None
    SCPClient = None

try:
    import frida
    print("[+] Frida instrumentation bindings imported successfully.")
except ImportError:
    frida = None

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ---------------------------------------------------------------------
# BUG BOUNTY RECON — STATIC ANALYSIS CONSTANTS
# ---------------------------------------------------------------------
ANDROID_NS = "http://schemas.android.com/apk/res/android"

DANGEROUS_PERMISSIONS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
    "CAMERA", "RECORD_AUDIO",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "CALL_PHONE", "PROCESS_OUTGOING_CALLS",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "READ_CALENDAR", "WRITE_CALENDAR",
    "BODY_SENSORS", "ACTIVITY_RECOGNITION",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
}

URL_PATTERN = re.compile(r"""https?://[^\s"'<>]+""")
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

SECRET_PATTERNS = {
    "Google API Key":         re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "AWS Access Key ID":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "Firebase DB URL":        re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "Slack Token":            re.compile(r"xox[baprs]-[0-9A-Za-z\-]+"),
    "JWT":                    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "Generic API Key/Secret": re.compile(
        r"""(?:api_key|apikey|secret|access_token)\s*[=:]\s*["']([0-9A-Za-z_\-]{16,})["']""",
        re.IGNORECASE),
}

RECON_TEXT_EXTENSIONS = {".smali", ".xml", ".json", ".js", ".txt", ".properties"}
RECON_SKIP_DIR_PREFIXES = ("drawable", "mipmap", "anim", "raw", "font", "color")
RECON_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

# ---------------------------------------------------------------------
# DYNAMIC TESTING — FRIDA CONSTANTS
# ---------------------------------------------------------------------
FRIDA_SERVER_REMOTE_PATH = "/data/local/tmp/frida-server"
FRIDA_SERVER_CACHE_DIR = os.path.normpath("tools/frida-server-cache")
FRIDA_SERVER_RELEASE_URL_TMPL = "https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}.xz"

SSL_PINNING_BYPASS_SCRIPT = os.path.normpath("frida_scripts/ssl_pinning_bypass.js")
ROOT_DETECTION_BYPASS_SCRIPT = os.path.normpath("frida_scripts/root_detection_bypass.js")

# ---------------------------------------------------------------------
# MOBSF-STYLE STATIC CODE VULNERABILITY RULES
# ---------------------------------------------------------------------
CODE_VULN_PATTERNS = {
    "Weak Hash Algorithm (MD5/SHA-1)": {
        "pattern": re.compile(r"Ljava/security/MessageDigest;->getInstance\(Ljava/lang/String;\).{0,80}?(?:MD5|SHA-1)", re.DOTALL),
        "severity": "medium",
    },
    "Weak Cipher (DES/ECB)": {
        "pattern": re.compile(r"Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;\).{0,80}?(?:DES|/ECB/)", re.DOTALL),
        "severity": "high",
    },
    "Insecure PRNG (java.util.Random)": {
        "pattern": re.compile(r"Ljava/util/Random;-><init>"),
        "severity": "low",
    },
    "WebView JavaScript Enabled": {
        "pattern": re.compile(r"Landroid/webkit/WebSettings;->setJavaScriptEnabled\(Z\)V"),
        "severity": "medium",
    },
    "WebView addJavascriptInterface": {
        "pattern": re.compile(r"Landroid/webkit/WebView;->addJavascriptInterface\("),
        "severity": "high",
    },
    "WebView File Access Enabled": {
        "pattern": re.compile(r"Landroid/webkit/WebSettings;->(?:setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs)\("),
        "severity": "medium",
    },
    "Custom X509TrustManager (review for empty checkServerTrusted)": {
        "pattern": re.compile(r"Ljavax/net/ssl/X509TrustManager;"),
        "severity": "medium",
    },
    "Custom HostnameVerifier (review for always-true verify)": {
        "pattern": re.compile(r"Ljavax/net/ssl/HostnameVerifier;"),
        "severity": "medium",
    },
    "External Storage Read/Write": {
        "pattern": re.compile(r"Landroid/os/Environment;->getExternalStorageDirectory\("),
        "severity": "low",
    },
}

ANDROID_DEBUG_CERT_DN = "CN=Android Debug, O=Android, C=US"


class NKCyberSuiteMobile(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("MobiSuite v1.2.0")
        self.geometry("1100x920")
        self.minsize(1000, 840)
        
        # SAFE CROSS-PLATFORM WINDOW GEOMETRY DECORATION UNLOCK
        self.resizable(True, True)
        if IS_LINUX:
            self.attributes('-type', 'normal')
        self.update_idletasks()
        
        # Operational Context State Trackers
        self.target_apk = ""
        self.rebuild_dir = ""
        self.unsigned_apk_path = "" 
        self.selected_merge_dir = ""
        self.install_target_apk = ""  
        self.discovered_android_apps = {}  
        self.discovered_ios_apps = {}
        self.ios_dest_dir = ""

        self.recon_target_dir = ""
        self.recon_manifest_info = {}
        self.recon_findings = {"urls": set(), "ips": set(), "secrets": [], "code_vulns": []}
        self.recon_scope_list = []
        self.recon_scope_results = {"in_scope": [], "out_of_scope": []}
        self.recon_signature_info = {}

        self.discovered_dynamic_apps = {}
        self.dynamic_target_package = ""
        self.device_abi = ""
        self.device_root_ready = False
        self.frida_device = None
        self.frida_session = None
        self.frida_script = None
        self.frida_server_process = None
        self.custom_frida_script_path = ""

        ext = ".exe" if sys.platform == "win32" else ""
        self.bin_names = [f"adb{ext}", "apktool.jar", "APKEditor.jar", f"zipalign{ext}", "apksigner.jar"]
        self.bin_status_labels = {}
        self.pip_packages = ["customtkinter", "paramiko", "scp", "pyinstaller", "cryptography", "frida"]
        self.pip_status_labels = {}

        # ---------------------------------------------------------------------
        # LEFT NAVIGATION SIDEBAR RAIL
        # ---------------------------------------------------------------------
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1A1A1E")
        self.sidebar.pack(side="left", fill="y")
        
        logo_main = ctk.CTkLabel(self.sidebar, text="💎 MOBISUITE", font=ctk.CTkFont(size=18, weight="bold"), text_color="#00E5FF")
        logo_main.pack(padx=20, pady=(30, 0))
        logo_sub = ctk.CTkLabel(self.sidebar, text="[ M O B I L E ]", font=ctk.CTkFont(size=11, weight="normal"), text_color="#7A7A80")
        logo_sub.pack(padx=20, pady=(2, 25))
        
        self.btn_nav_android = ctk.CTkButton(self.sidebar, text="🤖 Android Utilities", 
                                            fg_color="#2A2B36", hover_color="#3D3F4D", height=40, anchor="w",
                                            command=lambda: self.switch_deck_context("android"))
        self.btn_nav_android.pack(padx=15, pady=5, fill="x")
        
        self.btn_nav_ios = ctk.CTkButton(self.sidebar, text="🍏 iOS Utilities", 
                                        fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                        command=lambda: self.switch_deck_context("ios"))
        self.btn_nav_ios.pack(padx=15, pady=5, fill="x")

        self.btn_nav_settings = ctk.CTkButton(self.sidebar, text="⚙️ Environment Settings", 
                                            fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                            command=lambda: self.switch_deck_context("settings"))
        self.btn_nav_settings.pack(padx=15, pady=5, fill="x")

        self.btn_nav_console = ctk.CTkButton(self.sidebar, text="📟 Live Terminal Logs", 
                                            fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                            command=lambda: self.switch_deck_context("console"))
        self.btn_nav_console.pack(padx=15, pady=5, fill="x")

        self.btn_nav_recon = ctk.CTkButton(self.sidebar, text="🎯 Bug Bounty Recon",
                                            fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                            command=lambda: self.switch_deck_context("recon"))
        self.btn_nav_recon.pack(padx=15, pady=5, fill="x")

        self.btn_nav_dynamic = ctk.CTkButton(self.sidebar, text="🕵 Dynamic Testing",
                                              fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                              command=lambda: self.switch_deck_context("dynamic"))
        self.btn_nav_dynamic.pack(padx=15, pady=5, fill="x")

        copyright_lbl = ctk.CTkLabel(self.sidebar, text="© 2026 Nilesh Kale\nAll Rights Reserved\nVersion 1.2.0", font=ctk.CTkFont(size=10), text_color="gray", justify="center")
        copyright_lbl.pack(side="bottom", pady=15)

        # ---------------------------------------------------------------------
        # AUTOMATIC HARDWARE CONNECTION STATUS HUD (BOTTOM BAR 2/2)
        # ---------------------------------------------------------------------
        self.hud_bar = ctk.CTkFrame(self, height=35, corner_radius=0, fg_color="#141416", border_color="#222226", border_width=1)
        self.hud_bar.pack(side="bottom", fill="x")
        self.hud_bar.pack_propagate(False)

        self.lbl_hud_android = ctk.CTkLabel(self.hud_bar, text="🔴 Android: Disconnected", font=ctk.CTkFont(size=11, weight="bold"), text_color="#FF1744")
        self.lbl_hud_android.pack(side="left", padx=20)

        self.lbl_hud_ios = ctk.CTkLabel(self.hud_bar, text="🔴 iOS: Endpoint Offline", font=ctk.CTkFont(size=11, weight="bold"), text_color="#FF1744")
        self.lbl_hud_ios.pack(side="left", padx=20)

        # ---------------------------------------------------------------------
        # GLOBAL BACKEND TASK PROGRESS TRACKER HUD (BOTTOM BAR 1/2)
        # ---------------------------------------------------------------------
        self.task_hud_bar = ctk.CTkFrame(self, height=40, corner_radius=0, fg_color="#1A1A22", border_color="#2B2B36", border_width=1)
        self.task_hud_bar.pack(side="bottom", fill="x")
        self.task_hud_bar.pack_propagate(False)

        lbl_task_title = ctk.CTkLabel(self.task_hud_bar, text="CURRENT PIPELINE OPERATION:", font=ctk.CTkFont(size=10, weight="bold"), text_color="#7A7A80")
        lbl_task_title.pack(side="left", padx=(20, 5))

        self.lbl_task_desc = ctk.CTkLabel(self.task_hud_bar, text="None (System Idle)", font=ctk.CTkFont(size=12, weight="normal"), text_color="#FFFFFF")
        self.lbl_task_desc.pack(side="left", padx=5)

        self.lbl_task_badge = ctk.CTkLabel(self.task_hud_bar, text="🔵 IDLE", width=85, font=ctk.CTkFont(size=11, weight="bold"), text_color="#2196F3", fg_color="#0D47A1", corner_radius=4)
        self.lbl_task_badge.pack(side="right", padx=20, pady=6)

        # ---------------------------------------------------------------------
        # MAIN DECK DISPLAY CONTAINER (SCROLLABLE REFACTION)
        # ---------------------------------------------------------------------
        self.main_deck = ctk.CTkFrame(self, corner_radius=0, fg_color="#0F0F12")
        self.main_deck.pack(side="right", fill="both", expand=True)
        
        # PATCH: Native scroll wraps appended to capture multi-panel widgets overflows
        self.view_android = ctk.CTkScrollableFrame(self.main_deck, fg_color="transparent", label_text="")
        self.view_ios = ctk.CTkScrollableFrame(self.main_deck, fg_color="transparent", label_text="")
        self.view_settings = ctk.CTkScrollableFrame(self.main_deck, fg_color="transparent", label_text="")
        self.view_recon = ctk.CTkScrollableFrame(self.main_deck, fg_color="transparent", label_text="")
        self.view_dynamic = ctk.CTkScrollableFrame(self.main_deck, fg_color="transparent", label_text="")
        self.view_console = ctk.CTkFrame(self.main_deck, fg_color="transparent")

        self.generate_android_deck_ui()
        self.generate_ios_deck_ui()
        self.generate_settings_deck_ui()
        self.generate_recon_deck_ui()
        self.generate_dynamic_deck_ui()
        self.generate_console_deck_ui()
        
        self.switch_deck_context("android")
        
        threading.Thread(target=self.verify_and_download_dependencies, daemon=True).start()
        threading.Thread(target=self.device_connection_hud_ticker, daemon=True).start()

    def log(self, message):
        self.console_box.insert("end", message + "\n")
        self.console_box.see("end")

    def update_task_state(self, task_description, state_type):
        self.lbl_task_desc.configure(text=task_description)
        if state_type == "idle":
            self.lbl_task_badge.configure(text="🔵 IDLE", text_color="#2196F3", fg_color="#0D47A1")
        elif state_type == "running":
            self.lbl_task_badge.configure(text="🟡 RUNNING", text_color="#FFB300", fg_color="#FF6F00")
        elif state_type == "success":
            self.lbl_task_badge.configure(text="  SUCCESS  ", text_color="#00E676", fg_color="#1B5E20")
        elif state_type == "failed":
            self.lbl_task_badge.configure(text="🔴 FAILED", text_color="#FF1744", fg_color="#B71C1C")

    def switch_deck_context(self, target_deck):
        self.btn_nav_android.configure(fg_color="transparent", text_color="#A0A0A5")
        self.btn_nav_ios.configure(fg_color="transparent", text_color="#A0A0A5")
        self.btn_nav_settings.configure(fg_color="transparent", text_color="#A0A0A5")
        self.btn_nav_console.configure(fg_color="transparent", text_color="#A0A0A5")
        self.btn_nav_recon.configure(fg_color="transparent", text_color="#A0A0A5")
        self.btn_nav_dynamic.configure(fg_color="transparent", text_color="#A0A0A5")

        self.view_android.pack_forget()
        self.view_ios.pack_forget()
        self.view_settings.pack_forget()
        self.view_recon.pack_forget()
        self.view_dynamic.pack_forget()
        self.view_console.pack_forget()

        if target_deck == "android":
            self.btn_nav_android.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_android.pack(fill="both", expand=True, padx=5, pady=5)
        elif target_deck == "ios":
            self.btn_nav_ios.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_ios.pack(fill="both", expand=True, padx=5, pady=5)
        elif target_deck == "settings":
            self.btn_nav_settings.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_settings.pack(fill="both", expand=True, padx=5, pady=5)
            self.check_local_tools_inventory()
        elif target_deck == "console":
            self.btn_nav_console.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_console.pack(fill="both", expand=True, padx=15, pady=15)
        elif target_deck == "recon":
            self.btn_nav_recon.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_recon.pack(fill="both", expand=True, padx=5, pady=5)
        elif target_deck == "dynamic":
            self.btn_nav_dynamic.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_dynamic.pack(fill="both", expand=True, padx=5, pady=5)

    def generate_console_deck_ui(self):
        lbl = ctk.CTkLabel(self.view_console, text="Core Diagnostics & Assessment Stream Log", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(anchor="w", padx=10, pady=(5, 10))
        frame = ctk.CTkFrame(self.view_console, fg_color="#141416", border_color="#222226", border_width=1)
        frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.console_box = ctk.CTkTextbox(frame, fg_color="#09090B", text_color="#00E676", font=ctk.CTkFont(family="Consolas", size=13))
        self.console_box.pack(fill="both", expand=True, padx=12, pady=12)

    def device_connection_hud_ticker(self):
        while True:
            try:
                res = subprocess.run(["adb", "devices"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
                lines = [line.strip() for line in res.stdout.splitlines() if line.strip() and not line.startswith("List")]
                if lines:
                    dev_id = lines[0].split()[0]
                    self.lbl_hud_android.configure(text=f"🟢 Android: Connected [{dev_id}]", text_color="#00E676")
                else:
                    self.lbl_hud_android.configure(text="🔴 Android: Disconnected", text_color="#FF1744")
            except Exception:
                self.lbl_hud_android.configure(text="🔴 Android: Engine Unreachable", text_color="#FF1744")

            try:
                ip = self.ent_ios_ip.get().strip()
                if ip and ip != "192.168.137.73":
                    param = "-n" if sys.platform == "win32" else "-c"
                    ping_proc = subprocess.run(["ping", param, "1", "-w", "800", ip], capture_output=True, creationflags=SUBPROCESS_FLAGS)
                    if ping_proc.returncode == 0:
                        self.lbl_hud_ios.configure(text=f"🟢 iOS: SSH Endpoint Live [{ip}]", text_color="#00E676")
                    else:
                        self.lbl_hud_ios.configure(text="🔴 iOS: Endpoint Offline", text_color="#FF1744")
                else:
                    self.lbl_hud_ios.configure(text="⚪ iOS: Staged", text_color="gray")
            except Exception:
                self.lbl_hud_ios.configure(text="🔴 iOS: Check IP Syntax", text_color="#FF1744")
            time.sleep(4.0)

    def generate_settings_deck_ui(self):
        lbl = ctk.CTkLabel(self.view_settings, text="Core Environment Control Center", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(anchor="w", padx=10, pady=(5, 5))
        bin_card = ctk.CTkFrame(self.view_settings, fg_color="#16161A", corner_radius=6)
        bin_card.pack(fill="x", padx=5, pady=5)
        lbl_mon = ctk.CTkLabel(bin_card, text="Sub-Tool Binary Inventory Workspace Status", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF")
        lbl_mon.pack(anchor="w", padx=15, pady=(10, 5))

        for bin_file in self.bin_names:
            row = ctk.CTkFrame(bin_card, fg_color="#1E1E24", height=34, corner_radius=4)
            row.pack(fill="x", padx=15, pady=2)
            row.pack_propagate(False)
            ctk.CTkLabel(row, text=f"  🛠️  {bin_file}", font=ctk.CTkFont(size=11)).pack(side="left", padx=5)
            badge = ctk.CTkLabel(row, text="AUDITING...", font=ctk.CTkFont(size=11, weight="bold"), text_color="orange")
            badge.pack(side="right", padx=15)
            self.bin_status_labels[bin_file] = badge

        pip_card = ctk.CTkFrame(self.view_settings, fg_color="#16161A", corner_radius=6)
        pip_card.pack(fill="x", padx=5, pady=5)
        lbl_pip = ctk.CTkLabel(pip_card, text="Python Libraries & Pip Module Extensions Status", font=ctk.CTkFont(size=12, weight="bold"), text_color="#E040FB")
        lbl_pip.pack(anchor="w", padx=15, pady=(10, 5))

        for pkg in self.pip_packages:
            row = ctk.CTkFrame(pip_card, fg_color="#1E1E24", height=34, corner_radius=4)
            row.pack(fill="x", padx=15, pady=2)
            row.pack_propagate(False)
            ctk.CTkLabel(row, text=f"  📦  python -m pip install {pkg}", font=ctk.CTkFont(size=11, family="Consolas")).pack(side="left", padx=5)
            badge = ctk.CTkLabel(row, text="VERIFYING...", font=ctk.CTkFont(size=11, weight="bold"), text_color="orange")
            badge.pack(side="right", padx=15)
            self.pip_status_labels[pkg] = badge

        action_row = ctk.CTkFrame(self.view_settings, fg_color="transparent")
        action_row.pack(fill="x", padx=5, pady=5)
        btn_recheck = ctk.CTkButton(action_row, text="Refresh Status Map", fg_color="#37474F", hover_color="#455A64", command=self.check_local_tools_inventory)
        btn_recheck.pack(side="left", padx=5)
        btn_force_sync = ctk.CTkButton(action_row, text="Force System Sync & Repair", fg_color="#E65100", hover_color="#F57C00", command=self.trigger_manual_dependency_repair)
        btn_force_sync.pack(side="right", padx=5)

    def check_local_tools_inventory(self):
        tools_dir = os.path.normpath("tools")
        for bin_file in self.bin_names:
            local_exists = os.path.exists(os.path.join(tools_dir, bin_file))
            system_exists = shutil.which(bin_file.replace(".exe", "")) is not None if IS_LINUX else False
            if local_exists or system_exists:
                self.bin_status_labels[bin_file].configure(text="🟢 INSTALLED", text_color="#00E676")
            else:
                self.bin_status_labels[bin_file].configure(text="🔴 MISSING", text_color="#FF1744")

        for pkg in self.pip_packages:
            if importlib.util.find_spec(pkg) is not None:
                self.pip_status_labels[pkg].configure(text="🟢 INSTALLED VIA PIP", text_color="#00E676")
            else:
                self.pip_status_labels[pkg].configure(text="🔴 NOT FOUND IN PATH", text_color="#FF1744")

    def trigger_manual_dependency_repair(self):
        self.update_task_state("Downloading repository toolsets...", "running")
        self.log("\n[*] Running automated system structural integrity patch routines...")
        threading.Thread(target=self.verify_and_download_dependencies, daemon=True).start()

    def generate_android_deck_ui(self):
        lbl = ctk.CTkLabel(self.view_android, text="Android Operational Utilities Deck", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(anchor="w", padx=10, pady=(5, 5))
        
        card_0a = ctk.CTkFrame(self.view_android, fg_color="#16161A", corner_radius=6)
        card_0a.pack(fill="x", pady=4)
        lbl_0a = ctk.CTkLabel(card_0a, text="Step 0a: ADB Device Application Binary Puller (Handles Splits)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF")
        lbl_0a.pack(anchor="w", padx=15, pady=(6, 4))
        sub_0a = ctk.CTkFrame(card_0a, fg_color="transparent")
        sub_0a.pack(fill="x", padx=15, pady=(0, 10))
        self.btn_scan_adb = ctk.CTkButton(sub_0a, text="Scan USB Apps", width=110, fg_color="#0288D1", hover_color="#039BE5", command=self.start_android_package_fetch)
        self.btn_scan_adb.pack(side="left", padx=(0, 5))
        self.cbo_android_apps = ctk.CTkComboBox(sub_0a, values=["Click Scan to look up application lists..."], width=280)
        self.cbo_android_apps.pack(side="left", padx=5)
        self.btn_pull_adb = ctk.CTkButton(sub_0a, text="Pull Targets Folder", width=130, fg_color="#2E7D32", hover_color="#388E3C", command=self.start_android_apk_pull)
        self.btn_pull_adb.pack(side="right")

        card_0b = ctk.CTkFrame(self.view_android, fg_color="#16161A", corner_radius=6)
        card_0b.pack(fill="x", pady=4)
        lbl_0b = ctk.CTkLabel(card_0b, text="Step 0b: APKEditor App Bundle Split Architecture Merger (Optional)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#FFB300")
        lbl_0b.pack(anchor="w", padx=15, pady=(6, 4))
        sub_0b = ctk.CTkFrame(card_0b, fg_color="transparent")
        sub_0b.pack(fill="x", padx=15, pady=(0, 10))
        btn_sel_merge = ctk.CTkButton(sub_0b, text="Select Chunks Folder", width=140, fg_color="#37474F", hover_color="#455A64", command=self.browse_merge_folder)
        btn_sel_merge.pack(side="left", padx=(0, 5))
        self.lbl_merge_dir = ctk.CTkLabel(sub_0b, text="No Split App Folder Selected", text_color="gray", anchor="w")
        self.lbl_merge_dir.pack(side="left", padx=5)
        self.btn_run_merge = ctk.CTkButton(sub_0b, text="Merge via APKEditor", width=130, fg_color="#E65100", hover_color="#F57C00", command=self.start_apk_merger)
        self.btn_run_merge.pack(side="right")

        card_1 = ctk.CTkFrame(self.view_android, fg_color="#16161A", corner_radius=6)
        card_1.pack(fill="x", pady=4)
        lbl_1 = ctk.CTkLabel(card_1, text="Step 1: Reverse Engineering Assembly Pipeline (Apktool)", font=ctk.CTkFont(size=12, weight="bold"))
        lbl_1.pack(anchor="w", padx=15, pady=(6, 4))
        sub_1 = ctk.CTkFrame(card_1, fg_color="transparent")
        sub_1.pack(fill="x", padx=15, pady=(0, 10))
        btn_br_apk = ctk.CTkButton(sub_1, text="Browse Target APK", width=140, command=self.browse_apk)
        btn_br_apk.pack(side="left", padx=(0, 5))
        self.lbl_apk = ctk.CTkLabel(sub_1, text="No active APK loaded as tracking target.", text_color="#A0A0A5", anchor="w")
        self.lbl_apk.pack(side="left", padx=5)
        self.btn_decompile = ctk.CTkButton(sub_1, text="Decompile", width=110, fg_color="#5E35B1", hover_color="#6F35B1", state="disabled", command=self.start_decompile)
        self.btn_decompile.pack(side="right")

        card_2 = ctk.CTkFrame(self.view_android, fg_color="#16161A", corner_radius=6)
        card_2.pack(fill="x", pady=4)
        lbl_2 = ctk.CTkLabel(card_2, text="Step 2: Package Compilation Reassembly & Jar Signer", font=ctk.CTkFont(size=12, weight="bold"))
        lbl_2.pack(anchor="w", padx=15, pady=(6, 4))
        sub_2 = ctk.CTkFrame(card_2, fg_color="transparent")
        sub_2.pack(fill="x", padx=15, pady=(0, 10))
        btn_br_dir = ctk.CTkButton(sub_2, text="Select Modded Folder", width=140, command=self.browse_folder)
        btn_br_dir.pack(side="left", padx=(0, 5))
        self.lbl_dir = ctk.CTkLabel(sub_2, text="No modified directory path selected.", text_color="#A0A0A5", anchor="w")
        self.lbl_dir.pack(side="left", padx=5)
        self.btn_rebuild = ctk.CTkButton(sub_2, text="Rebuild & Sign", width=110, fg_color="#1565C0", hover_color="#1E88E5", state="disabled", command=self.start_rebuild)
        self.btn_rebuild.pack(side="right")

        card_3 = ctk.CTkFrame(self.view_android, fg_color="#16161A", corner_radius=6)
        card_3.pack(fill="x", pady=4)
        lbl_3 = ctk.CTkLabel(card_3, text="Step 3: Standalone Production Alignment & Signing Task Execution", font=ctk.CTkFont(size=12, weight="bold"), text_color="#E91E63")
        lbl_3.pack(anchor="w", padx=15, pady=(6, 4))
        sub_3 = ctk.CTkFrame(card_3, fg_color="transparent")
        sub_3.pack(fill="x", padx=15, pady=(0, 10))
        btn_br_sign = ctk.CTkButton(sub_3, text="Browse Manual APK", width=140, command=self.browse_unsigned_apk)
        btn_br_sign.pack(side="left", padx=(0, 5))
        self.lbl_sign_apk = ctk.CTkLabel(sub_3, text="No manual unsigned APK binary staged.", text_color="#A0A0A5", anchor="w")
        self.lbl_sign_apk.pack(side="left", padx=5)
        self.btn_sign_only = ctk.CTkButton(sub_3, text="Zipalign & Sign", width=110, fg_color="#C2185B", hover_color="#D81B60", state="disabled", command=self.start_sign_only)
        self.btn_sign_only.pack(side="right")

        card_4 = ctk.CTkFrame(self.view_android, fg_color="#16161A", corner_radius=6)
        card_4.pack(fill="x", pady=4)
        lbl_4 = ctk.CTkLabel(card_4, text="Step 4: Standalone ADB Installation Engine & Pipeline Extension", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E676")
        lbl_4.pack(anchor="w", padx=15, pady=(6, 4))
        
        sub_4_file = ctk.CTkFrame(card_4, fg_color="transparent")
        sub_4_file.pack(fill="x", padx=15, pady=5)
        btn_br_install = ctk.CTkButton(sub_4_file, text="Select Custom APK", width=140, fg_color="#37474F", hover_color="#455A64", command=self.browse_install_target_apk)
        btn_br_install.pack(side="left", padx=(0, 5))
        self.lbl_install_apk = ctk.CTkLabel(sub_4_file, text="No target binary package staged for device deployment.", text_color="#A0A0A5", anchor="w")
        self.lbl_install_apk.pack(side="left", padx=5)

        param_frame = ctk.CTkFrame(card_4, fg_color="#1E1E24", corner_radius=4, border_color="#2B2B36", border_width=1)
        param_frame.pack(fill="x", padx=15, pady=(5, 10))
        lbl_param_title = ctk.CTkLabel(param_frame, text="🕹️ ADVANCED TERMINAL PIPELINE SEQUENCE EXECUTION (CUSTOM PARAMS)", font=ctk.CTkFont(size=10, weight="bold"), text_color="#7A7A80")
        lbl_param_title.pack(anchor="w", padx=12, pady=(8, 2))
        
        radio_row = ctk.CTkFrame(param_frame, fg_color="transparent")
        radio_row.pack(fill="x", padx=12, pady=4)
        self.install_mode_var = tk.StringVar(value="standard")
        
        rad_std = ctk.CTkRadioButton(radio_row, text="Standard Install (-r)", variable=self.install_mode_var, value="standard", command=self.sync_custom_adb_cmd_string)
        rad_std.pack(side="left", padx=(0, 10))
        rad_down = ctk.CTkRadioButton(radio_row, text="Force Downgrade (-d)", variable=self.install_mode_var, value="downgrade", command=self.sync_custom_adb_cmd_string)
        rad_down.pack(side="left", padx=10)
        rad_test = ctk.CTkRadioButton(radio_row, text="Allow Test Apps (-t)", variable=self.install_mode_var, value="test", command=self.sync_custom_adb_cmd_string)
        rad_test.pack(side="left", padx=10)
        rad_vend = ctk.CTkRadioButton(radio_row, text="Play Store Fake (-i Vending)", variable=self.install_mode_var, value="vending", command=self.sync_custom_adb_cmd_string)
        rad_vend.pack(side="left", padx=10)

        entry_row = ctk.CTkFrame(param_frame, fg_color="transparent")
        entry_row.pack(fill="x", padx=12, pady=(4, 12))
        ctk.CTkLabel(entry_row, text="Custom Flag Override:", font=ctk.CTkFont(size=11)).pack(side="left", padx=(0, 5))
        self.ent_custom_adb = ctk.CTkEntry(entry_row, font=ctk.CTkFont(family="Consolas", size=12), text_color="#00E5FF")
        self.ent_custom_adb.pack(side="left", fill="x", expand=True, padx=5)
        self.ent_custom_adb.insert(0, "adb install -r")

        btn_row = ctk.CTkFrame(card_4, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(0, 12))
        self.btn_execute_install = ctk.CTkButton(btn_row, text="Push Package to Device", width=160, fg_color="#2E7D32", hover_color="#388E3C", state="disabled", command=self.start_threaded_adb_sideload)
        self.btn_execute_install.pack(side="right")

    def generate_ios_deck_ui(self):
        lbl = ctk.CTkLabel(self.view_ios, text="iOS Operational Utilities Deck", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(anchor="w", padx=10, pady=(5, 5))
        
        card_ssh = ctk.CTkFrame(self.view_ios, fg_color="#16161A", corner_radius=6)
        card_ssh.pack(fill="x", pady=5)
        lbl_ssh = ctk.CTkLabel(card_ssh, text="Step 1: Jailbreak SSH Transport Link Context Parameters", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF")
        lbl_ssh.pack(anchor="w", padx=15, pady=(6, 6))
        
        sub_ssh = ctk.CTkFrame(card_ssh, fg_color="transparent")
        sub_ssh.pack(fill="x", padx=15, pady=(0, 10))
        ctk.CTkLabel(sub_ssh, text="IP:").pack(side="left", padx=(0, 2))
        self.ent_ios_ip = ctk.CTkEntry(sub_ssh, width=120); self.ent_ios_ip.insert(0, "192.168.137.73"); self.ent_ios_ip.pack(side="left", padx=(0, 5))
        ctk.CTkLabel(sub_ssh, text="User:").pack(side="left", padx=(5, 2))
        self.ent_ios_user = ctk.CTkEntry(sub_ssh, width=60); self.ent_ios_user.insert(0, "root"); self.ent_ios_user.pack(side="left", padx=(0, 5))
        ctk.CTkLabel(sub_ssh, text="Pass:").pack(side="left", padx=(5, 2))
        self.ent_ios_pass = ctk.CTkEntry(sub_ssh, width=70, show="*"); self.ent_ios_pass.insert(0, "alpine"); self.ent_ios_pass.pack(side="left", padx=(0, 5))
        self.btn_fetch_apps = ctk.CTkButton(sub_ssh, text="Scan App Bundles", fg_color="#6A1B9A", hover_color="#7B1FA2", command=self.start_ios_app_fetch)
        self.btn_fetch_apps.pack(side="right")

        card_sel = ctk.CTkFrame(self.view_ios, fg_color="#16161A", corner_radius=6)
        card_sel.pack(fill="x", pady=5)
        lbl_sel = ctk.CTkLabel(card_sel, text="Step 2: Track Target Decrypted Bundle", font=ctk.CTkFont(size=12, weight="bold"))
        lbl_sel.pack(anchor="w", padx=15, pady=(6, 4))
        self.cbo_ios_apps = ctk.CTkComboBox(card_sel, values=["Run Remote Scan tracking logic first..."])
        self.cbo_ios_apps.pack(padx=15, pady=(0, 12), fill="x")

        card_pack = ctk.CTkFrame(self.view_ios, fg_color="#16161A", corner_radius=6)
        card_pack.pack(fill="x", pady=5)
        lbl_pack = ctk.CTkLabel(card_pack, text="Step 3: Staging Automation & Local IPA Package Forging", font=ctk.CTkFont(size=12, weight="bold"))
        lbl_pack.pack(anchor="w", padx=15, pady=(6, 4))
        sub_pack = ctk.CTkFrame(card_pack, fg_color="transparent")
        sub_pack.pack(fill="x", padx=15, pady=(0, 10))
        btn_br_ios = ctk.CTkButton(sub_pack, text="Select Workpath Folder", width=140, fg_color="#37474F", hover_color="#455A64", command=self.ios_browse_dest)
        btn_br_ios.pack(side="left", padx=(0, 5))
        self.lbl_ios_dest = ctk.CTkLabel(sub_pack, text="No local processing path specified.", text_color="#A0A0A5", anchor="w")
        self.lbl_ios_dest.pack(side="left", padx=5)
        self.btn_build_ipa = ctk.CTkButton(sub_pack, text="Build Signed .ipa", width=120, fg_color="#00C853", hover_color="#00E676", command=self.start_ipa_build)
        self.btn_build_ipa.pack(side="right")

    def generate_recon_deck_ui(self):
        lbl = ctk.CTkLabel(self.view_recon, text="Bug Bounty Recon Toolkit", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(anchor="w", padx=10, pady=(5, 5))

        card_r0 = ctk.CTkFrame(self.view_recon, fg_color="#16161A", corner_radius=6)
        card_r0.pack(fill="x", pady=4)
        lbl_r0 = ctk.CTkLabel(card_r0, text="Step 1: Recon Target - Decompiled Project Folder", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF")
        lbl_r0.pack(anchor="w", padx=15, pady=(6, 4))
        sub_r0 = ctk.CTkFrame(card_r0, fg_color="transparent")
        sub_r0.pack(fill="x", padx=15, pady=(0, 10))
        btn_br_recon = ctk.CTkButton(sub_r0, text="Select Decompiled Folder", width=170, command=self.browse_recon_target)
        btn_br_recon.pack(side="left", padx=(0, 5))
        self.lbl_recon_dir = ctk.CTkLabel(sub_r0, text="No recon target folder selected.", text_color="#A0A0A5", anchor="w")
        self.lbl_recon_dir.pack(side="left", padx=5)
        btn_use_last = ctk.CTkButton(sub_r0, text="Use Last Decompiled Output", width=170, fg_color="#37474F", hover_color="#455A64", command=self.use_last_decompiled_as_recon_target)
        btn_use_last.pack(side="right")

        card_rsig = ctk.CTkFrame(self.view_recon, fg_color="#16161A", corner_radius=6)
        card_rsig.pack(fill="x", pady=4)
        lbl_rsig = ctk.CTkLabel(card_rsig, text="Step 2: APK Signature & Hash Analysis", font=ctk.CTkFont(size=12, weight="bold"), text_color="#FF8A65")
        lbl_rsig.pack(anchor="w", padx=15, pady=(6, 4))
        sub_rsig = ctk.CTkFrame(card_rsig, fg_color="transparent")
        sub_rsig.pack(fill="x", padx=15, pady=(0, 10))
        self.btn_analyze_signature = ctk.CTkButton(sub_rsig, text="Analyze Signature & Hashes", width=190, fg_color="#5E35B1", hover_color="#6F35B1", command=self.start_signature_analysis)
        self.btn_analyze_signature.pack(side="left", padx=(0, 5))
        self.lbl_signature_summary = ctk.CTkLabel(sub_rsig, text="No signature analysis run yet (uses the active target APK).", text_color="#A0A0A5", anchor="w")
        self.lbl_signature_summary.pack(side="left", padx=5)

        card_r1 = ctk.CTkFrame(self.view_recon, fg_color="#16161A", corner_radius=6)
        card_r1.pack(fill="x", pady=4)
        lbl_r1 = ctk.CTkLabel(card_r1, text="Step 3: Manifest Attack Surface Extraction", font=ctk.CTkFont(size=12, weight="bold"), text_color="#FFB300")
        lbl_r1.pack(anchor="w", padx=15, pady=(6, 4))
        sub_r1 = ctk.CTkFrame(card_r1, fg_color="transparent")
        sub_r1.pack(fill="x", padx=15, pady=(0, 10))
        self.btn_extract_manifest = ctk.CTkButton(sub_r1, text="Extract Attack Surface", width=170, fg_color="#5E35B1", hover_color="#6F35B1", state="disabled", command=self.start_manifest_extraction)
        self.btn_extract_manifest.pack(side="left", padx=(0, 5))
        self.lbl_manifest_summary = ctk.CTkLabel(sub_r1, text="No manifest analyzed yet.", text_color="#A0A0A5", anchor="w")
        self.lbl_manifest_summary.pack(side="left", padx=5)

        card_r2 = ctk.CTkFrame(self.view_recon, fg_color="#16161A", corner_radius=6)
        card_r2.pack(fill="x", pady=4)
        lbl_r2 = ctk.CTkLabel(card_r2, text="Step 4: Endpoint, Secret & Code Vulnerability Scan (Decompiled Source)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#E91E63")
        lbl_r2.pack(anchor="w", padx=15, pady=(6, 4))
        sub_r2 = ctk.CTkFrame(card_r2, fg_color="transparent")
        sub_r2.pack(fill="x", padx=15, pady=(0, 10))
        self.btn_scan_source = ctk.CTkButton(sub_r2, text="Scan Decompiled Source", width=170, fg_color="#C2185B", hover_color="#D81B60", state="disabled", command=self.start_source_scan)
        self.btn_scan_source.pack(side="left", padx=(0, 5))
        self.lbl_scan_summary = ctk.CTkLabel(sub_r2, text="No source scan run yet.", text_color="#A0A0A5", anchor="w")
        self.lbl_scan_summary.pack(side="left", padx=5)

        card_r3 = ctk.CTkFrame(self.view_recon, fg_color="#16161A", corner_radius=6)
        card_r3.pack(fill="x", pady=4)
        lbl_r3 = ctk.CTkLabel(card_r3, text="Step 5: Bug Bounty Scope Matcher", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E676")
        lbl_r3.pack(anchor="w", padx=15, pady=(6, 4))
        lbl_r3_hint = ctk.CTkLabel(card_r3, text="Paste in-scope domains, one per line. Use *.example.com for domain + subdomains.", font=ctk.CTkFont(size=10), text_color="#7A7A80")
        lbl_r3_hint.pack(anchor="w", padx=15, pady=(0, 4))
        self.txt_scope = ctk.CTkTextbox(card_r3, height=90, fg_color="#09090B", text_color="#00E5FF", font=ctk.CTkFont(family="Consolas", size=12))
        self.txt_scope.pack(fill="x", padx=15, pady=(0, 8))
        self.btn_match_scope = ctk.CTkButton(card_r3, text="Match Discovered URLs to Scope", fg_color="#2E7D32", hover_color="#388E3C", command=self.start_scope_match)
        self.btn_match_scope.pack(padx=15, pady=(0, 10), anchor="e")

        card_r4 = ctk.CTkFrame(self.view_recon, fg_color="#16161A", corner_radius=6)
        card_r4.pack(fill="x", pady=4)
        lbl_r4 = ctk.CTkLabel(card_r4, text="Step 6: Export Recon Report", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF")
        lbl_r4.pack(anchor="w", padx=15, pady=(6, 4))
        self.btn_export_recon = ctk.CTkButton(card_r4, text="Export Markdown Report", fg_color="#0288D1", hover_color="#039BE5", command=self.export_recon_report)
        self.btn_export_recon.pack(padx=15, pady=(0, 10), anchor="e")

        card_r5 = ctk.CTkFrame(self.view_recon, fg_color="#16161A", corner_radius=6)
        card_r5.pack(fill="both", expand=True, pady=4)
        lbl_r5 = ctk.CTkLabel(card_r5, text="Structured Recon Findings Summary", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF")
        lbl_r5.pack(anchor="w", padx=15, pady=(6, 4))
        self.recon_results_box = ctk.CTkTextbox(card_r5, fg_color="#09090B", text_color="#00E676", font=ctk.CTkFont(family="Consolas", size=12), height=260)
        self.recon_results_box.pack(fill="both", expand=True, padx=15, pady=(0, 12))

    def generate_dynamic_deck_ui(self):
        lbl = ctk.CTkLabel(self.view_dynamic, text="Dynamic Testing Toolkit (Frida)", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(anchor="w", padx=10, pady=(5, 5))
        lbl_warn = ctk.CTkLabel(self.view_dynamic, text="Requires a rooted device/emulator. Only use against apps you are authorized to test.",
                                 font=ctk.CTkFont(size=10), text_color="#FF8A65")
        lbl_warn.pack(anchor="w", padx=10, pady=(0, 8))

        card_d0 = ctk.CTkFrame(self.view_dynamic, fg_color="#16161A", corner_radius=6)
        card_d0.pack(fill="x", pady=4)
        lbl_d0 = ctk.CTkLabel(card_d0, text="Step 1: Device Environment & Frida Server", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF")
        lbl_d0.pack(anchor="w", padx=15, pady=(6, 4))
        sub_d0 = ctk.CTkFrame(card_d0, fg_color="transparent")
        sub_d0.pack(fill="x", padx=15, pady=(0, 6))
        btn_detect_env = ctk.CTkButton(sub_d0, text="Detect Device Environment", width=190, fg_color="#37474F", hover_color="#455A64", command=self.start_device_detection)
        btn_detect_env.pack(side="left", padx=(0, 5))
        self.lbl_device_env = ctk.CTkLabel(sub_d0, text="Device environment not detected yet.", text_color="#A0A0A5", anchor="w")
        self.lbl_device_env.pack(side="left", padx=5)
        sub_d0b = ctk.CTkFrame(card_d0, fg_color="transparent")
        sub_d0b.pack(fill="x", padx=15, pady=(0, 10))
        self.btn_deploy_frida = ctk.CTkButton(sub_d0b, text="Deploy Frida Server", width=190, fg_color="#5E35B1", hover_color="#6F35B1", command=self.start_frida_server_deploy)
        self.btn_deploy_frida.pack(side="left", padx=(0, 5))
        self.lbl_frida_server_status = ctk.CTkLabel(sub_d0b, text="Frida server not deployed yet.", text_color="#A0A0A5", anchor="w")
        self.lbl_frida_server_status.pack(side="left", padx=5)

        card_d1 = ctk.CTkFrame(self.view_dynamic, fg_color="#16161A", corner_radius=6)
        card_d1.pack(fill="x", pady=4)
        lbl_d1 = ctk.CTkLabel(card_d1, text="Step 2: Target Application", font=ctk.CTkFont(size=12, weight="bold"), text_color="#FFB300")
        lbl_d1.pack(anchor="w", padx=15, pady=(6, 4))
        sub_d1 = ctk.CTkFrame(card_d1, fg_color="transparent")
        sub_d1.pack(fill="x", padx=15, pady=(0, 10))
        btn_scan_dyn_apps = ctk.CTkButton(sub_d1, text="Scan Installed Apps", width=150, fg_color="#0288D1", hover_color="#039BE5", command=self.start_dynamic_app_scan)
        btn_scan_dyn_apps.pack(side="left", padx=(0, 5))
        self.cbo_dynamic_apps = ctk.CTkComboBox(sub_d1, values=["Click Scan to look up application lists..."], width=280)
        self.cbo_dynamic_apps.pack(side="left", padx=5)

        card_d2 = ctk.CTkFrame(self.view_dynamic, fg_color="#16161A", corner_radius=6)
        card_d2.pack(fill="x", pady=4)
        lbl_d2 = ctk.CTkLabel(card_d2, text="Step 3: Bypass Script Runner", font=ctk.CTkFont(size=12, weight="bold"), text_color="#E91E63")
        lbl_d2.pack(anchor="w", padx=15, pady=(6, 4))
        sub_d2 = ctk.CTkFrame(card_d2, fg_color="transparent")
        sub_d2.pack(fill="x", padx=15, pady=(0, 10))
        self.btn_run_ssl_bypass = ctk.CTkButton(sub_d2, text="Run SSL Pinning Bypass", width=170, fg_color="#C2185B", hover_color="#D81B60", command=lambda: self.start_bypass_script("ssl"))
        self.btn_run_ssl_bypass.pack(side="left", padx=(0, 5))
        self.btn_run_root_bypass = ctk.CTkButton(sub_d2, text="Run Root Detection Bypass", width=190, fg_color="#C2185B", hover_color="#D81B60", command=lambda: self.start_bypass_script("root"))
        self.btn_run_root_bypass.pack(side="left", padx=5)
        self.btn_run_both_bypass = ctk.CTkButton(sub_d2, text="Run Both", width=100, fg_color="#AD1457", hover_color="#C2185B", command=lambda: self.start_bypass_script("both"))
        self.btn_run_both_bypass.pack(side="left", padx=5)
        self.btn_detach_dynamic = ctk.CTkButton(sub_d2, text="Detach", width=100, fg_color="#37474F", hover_color="#455A64", command=self.stop_dynamic_session)
        self.btn_detach_dynamic.pack(side="right")

        sub_d2b = ctk.CTkFrame(card_d2, fg_color="transparent")
        sub_d2b.pack(fill="x", padx=15, pady=(0, 10))
        btn_load_custom_script = ctk.CTkButton(sub_d2b, text="Load Custom Script...", width=170, fg_color="#37474F", hover_color="#455A64", command=self.browse_custom_frida_script)
        btn_load_custom_script.pack(side="left", padx=(0, 5))
        self.lbl_custom_script = ctk.CTkLabel(sub_d2b, text="No custom script loaded.", text_color="#A0A0A5", anchor="w")
        self.lbl_custom_script.pack(side="left", padx=5)
        self.btn_run_custom_bypass = ctk.CTkButton(sub_d2b, text="Run Custom Script", width=150, fg_color="#AD1457", hover_color="#C2185B", state="disabled", command=lambda: self.start_bypass_script("custom"))
        self.btn_run_custom_bypass.pack(side="right")

        card_d4 = ctk.CTkFrame(self.view_dynamic, fg_color="#16161A", corner_radius=6)
        card_d4.pack(fill="both", expand=True, pady=4)
        lbl_d4 = ctk.CTkLabel(card_d4, text="Dynamic Testing Results & Console", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF")
        lbl_d4.pack(anchor="w", padx=15, pady=(6, 4))
        self.dynamic_results_box = ctk.CTkTextbox(card_d4, fg_color="#09090B", text_color="#00E676", font=ctk.CTkFont(family="Consolas", size=12), height=260)
        self.dynamic_results_box.pack(fill="both", expand=True, padx=15, pady=(0, 12))

    def refresh_interface_locks(self):
        self.btn_decompile.configure(state="normal" if self.target_apk else "disabled")
        self.btn_rebuild.configure(state="normal" if self.rebuild_dir else "disabled")
        self.btn_sign_only.configure(state="normal" if self.unsigned_apk_path else "disabled")

    def browse_apk(self):
        filepath = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        if filepath:
            self.target_apk = filepath
            self.lbl_apk.configure(text=os.path.basename(self.target_apk), text_color="#FFFFFF")
            self.btn_decompile.configure(state="normal")

    def browse_folder(self):
        folderpath = filedialog.askdirectory(title="Select Target Decompiled Folder")
        if folderpath:
            norm_path = os.path.normpath(folderpath)
            if not os.path.exists(os.path.join(norm_path, "apktool.yml")):
                messagebox.showerror("Validation Error", "Invalid Target Directory!\n\nThe selected folder is missing the 'apktool.yml' file requirement.")
                self.rebuild_dir = ""
                self.lbl_dir.configure(text="No modified directory path selected.", text_color="#A0A0A5")
                self.btn_rebuild.configure(state="disabled")
                self.update_task_state("Invalid decompiled project folder structure.", "failed")
            else:
                self.rebuild_dir = norm_path
                self.lbl_dir.configure(text=os.path.basename(self.rebuild_dir), text_color="#00E676")
                self.btn_rebuild.configure(state="normal")
                self.update_task_state("Modded directory structural validation passed.", "idle")

    def browse_recon_target(self):
        folderpath = filedialog.askdirectory(title="Select Decompiled Apktool Project Folder")
        if folderpath:
            self._validate_and_set_recon_target(folderpath)

    def use_last_decompiled_as_recon_target(self):
        if not self.target_apk:
            messagebox.showwarning("No Target", "No APK has been decompiled yet on the Android tab.")
            return
        candidate = self.target_apk.replace(".apk", "_decompiled")
        if not os.path.isdir(candidate):
            messagebox.showwarning("Not Found", f"Expected decompiled folder not found:\n{candidate}")
            return
        self._validate_and_set_recon_target(candidate)

    def _validate_and_set_recon_target(self, folderpath):
        norm_path = os.path.normpath(folderpath)
        if not os.path.exists(os.path.join(norm_path, "apktool.yml")):
            messagebox.showerror("Validation Error", "Invalid Target Directory!\n\nThe selected folder is missing the 'apktool.yml' file requirement.")
            self.recon_target_dir = ""
            self.lbl_recon_dir.configure(text="No recon target folder selected.", text_color="#A0A0A5")
            self.btn_extract_manifest.configure(state="disabled")
            self.btn_scan_source.configure(state="disabled")
            self.update_task_state("Invalid recon target folder structure.", "failed")
        else:
            self.recon_target_dir = norm_path
            self.lbl_recon_dir.configure(text=os.path.basename(self.recon_target_dir), text_color="#00E676")
            self.btn_extract_manifest.configure(state="normal")
            self.btn_scan_source.configure(state="normal")
            self.update_task_state("Recon target folder validated.", "idle")

    def browse_unsigned_apk(self):
        filepath = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        if filepath:
            self.unsigned_apk_path = filepath
            self.lbl_sign_apk.configure(text=os.path.basename(self.unsigned_apk_path), text_color="#FFFFFF")
            self.btn_sign_only.configure(state="normal")

    def browse_install_target_apk(self):
        filepath = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        if filepath:
            self.install_target_apk = filepath
            self.lbl_install_apk.configure(text=os.path.basename(self.install_target_apk), text_color="#00E676")
            self.btn_execute_install.configure(state="normal")

    def sync_custom_adb_cmd_string(self):
        selected_mode = self.install_mode_var.get()
        self.ent_custom_adb.delete(0, "end")
        if selected_mode == "standard":
            self.ent_custom_adb.insert(0, "adb install -r")
        elif selected_mode == "downgrade":
            self.ent_custom_adb.insert(0, "adb install -r -d")
        elif selected_mode == "test":
            self.ent_custom_adb.insert(0, "adb install -r -t")
        elif selected_mode == "vending":
            self.ent_custom_adb.insert(0, "adb shell pm install -i com.android.vending -r")

    def start_threaded_adb_sideload(self):
        if not self.install_target_apk: return
        self.btn_execute_install.configure(state="disabled")
        self.update_task_state("[ADB] Deploying custom compiled binary target...", "running")
        threading.Thread(target=self.adb_sideload_worker, daemon=True).start()

    def adb_sideload_worker(self):
        try:
            raw_cmd_string = self.ent_custom_adb.get().strip()
            self.log(f"\n[*] Parsing execution query sequence parameters: {raw_cmd_string}")
            cmd_parts = raw_cmd_string.split()
            if "pm install" in raw_cmd_string:
                filename = os.path.basename(self.install_target_apk)
                remote_temp_path = f"/data/local/tmp/{filename}"
                self.log(f"[*] Staging archive onto partition: {remote_temp_path}")
                push_proc = subprocess.run(["adb", "push", self.install_target_apk, remote_temp_path], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
                if push_proc.returncode != 0:
                    self.log(f"[-] Push staging fault: {push_proc.stderr}")
                    self.update_task_state("Push target staging failed.", "failed")
                    self.btn_execute_install.configure(state="normal"); return
                exec_cmd = ["adb", "shell"] + cmd_parts[2:] + [remote_temp_path]
                self.log(f"[*] Executing pipeline deployment engine command array: {' '.join(exec_cmd)}")
                install_proc = subprocess.Popen(exec_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=SUBPROCESS_FLAGS)
                for line in iter(install_proc.stdout.readline, ''): self.log(line.strip())
                install_proc.stdout.close(); install_proc.wait()
                subprocess.run(["adb", "shell", "rm", remote_temp_path], creationflags=SUBPROCESS_FLAGS)
            else:
                exec_cmd = cmd_parts + [self.install_target_apk]
                self.log(f"[*] Calling standard installation deployment logic array: {' '.join(exec_cmd)}")
                install_proc = subprocess.Popen(exec_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=SUBPROCESS_FLAGS)
                for line in iter(install_proc.stdout.readline, ''): self.log(line.strip())
                install_proc.stdout.close(); install_proc.wait()
            self.log("\n--- Deployment Sequence Tasks Pipeline Completed ---")
            self.update_task_state("Installation execution loop done.", "success")
        except Exception as e:
            self.log(f"[-] ADB Installer sequence dropped parameter fault: {str(e)}")
            self.update_task_state("ADB Installation pipeline exception.", "failed")
        self.btn_execute_install.configure(state="normal")

    def verify_and_download_dependencies(self):
        for pkg in self.pip_packages:
            if importlib.util.find_spec(pkg) is None:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg] + KALI_FLAG, creationflags=SUBPROCESS_FLAGS)
                except Exception as ex: self.log(f"[-] Pip module extraction fault: {str(ex)}")

        tools_dir = os.path.normpath("tools")
        os.makedirs(tools_dir, exist_ok=True)
        dependencies = {
            "apktool.jar": "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.2/apktool_3.0.2.jar",
            "APKEditor.jar": "https://github.com/REAndroid/APKEditor/releases/download/V1.4.9/APKEditor-1.4.9.jar",
            "zipalign.exe" if sys.platform == "win32" else "zipalign": "https://github.com/Aki-S/android-sdk-zipalign-apksigner/raw/master/zipalign.exe" if sys.platform == "win32" else None,
            "apksigner.jar": "https://github.com/Aki-S/android-sdk-zipalign-apksigner/raw/master/apksigner.jar",
            "debug.keystore": "https://github.com/Aki-S/android-sdk-zipalign-apksigner/raw/master/debug.keystore"
        }
        for name, url in dependencies.items():
            if url is None: continue  
            target_path = os.path.join(tools_dir, name)
            if not os.path.exists(target_path):
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req) as response, open(target_path, 'wb') as out_file:
                        shutil.copyfileobj(response, out_file)
                except Exception: pass
        self.update_task_state("System Standby Ready", "idle")
        self.check_local_tools_inventory()

    def start_android_package_fetch(self):
        self.update_task_state("[ADB] Querying device database packages handles...", "running")
        threading.Thread(target=self.adb_fetch_packages_worker, daemon=True).start()

    def adb_fetch_packages_worker(self):
        try:
            cmd = ["adb", "shell", "pm", "list", "packages", "-3"]
            process = subprocess.run(cmd, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            if process.returncode != 0:
                self.update_task_state("ADB Interface Link dropped.", "failed"); return
            self.discovered_android_apps.clear()
            dropdown_entries = []
            raw_packages = [line.replace("package:", "").strip() for line in process.stdout.splitlines() if line.startswith("package:")]
            if not raw_packages: return

            for pkg in sorted(raw_packages):
                info_cmd = f"adb shell \"dumpsys package {pkg} | grep -i 'label=' | head -n 1\""
                info_proc = subprocess.run(info_cmd, capture_output=True, text=True, shell=True, creationflags=SUBPROCESS_FLAGS)
                raw_info = info_proc.stdout.strip()
                app_label = raw_info.split("label=")[-1].strip().replace("'", "").replace('"', '') if "label=" in raw_info else pkg.split(".")[-1].capitalize()
                display_string = f"{app_label} ({pkg})"
                self.discovered_android_apps[display_string] = (pkg, app_label)
                dropdown_entries.append(display_string)

            self.cbo_android_apps.configure(values=dropdown_entries)
            self.cbo_android_apps.set(dropdown_entries[0])
            self.update_task_state("Applications layout synced.", "success")
        except Exception: self.update_task_state("ADB Parser unexpected crash.", "failed")

    def start_android_apk_pull(self):
        selected_display = self.cbo_android_apps.get()
        if not selected_display or "Scan" in selected_display: return
        target_pkg, app_label = self.discovered_android_apps[selected_display]
        parent_folder = filedialog.askdirectory(title="Choose Parent Storage Location Workspace")
        if not parent_folder: return
        safe_app_label = "".join(c for c in app_label if c.isalnum() or c in (" ", "_", "-")).strip()
        app_target_dir = os.path.normpath(os.path.join(parent_folder, safe_app_label))
        self.update_task_state(f"[ADB] Extracting {safe_app_label} binaries folder tree...", "running")
        threading.Thread(target=self.adb_apk_pull_worker, args=(target_pkg, app_target_dir), daemon=True).start()

    def adb_apk_pull_worker(self, package_id, app_dir):
        try:
            os.makedirs(app_dir, exist_ok=True)
            path_proc = subprocess.run(["adb", "shell", "pm", "path", package_id], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            remote_paths = [line.replace("package:", "").strip() for line in path_proc.stdout.splitlines() if line.startswith("package:")]
            if not remote_paths: return

            base_local_path = ""
            for index, remote_path in enumerate(remote_paths):
                remote_filename = remote_path.split("/")[-1]
                local_filename = f"{package_id}.apk" if len(remote_paths) == 1 else remote_filename
                temp_local_path = os.path.normpath(os.path.join(app_dir, f"temp_pull_{index}.apk"))
                final_local_path = os.path.normpath(os.path.join(app_dir, local_filename))

                pull_proc = subprocess.Popen(["adb", "pull", remote_path, temp_local_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=SUBPROCESS_FLAGS)
                pull_proc.wait()
                if os.path.exists(temp_local_path):
                    if os.path.exists(final_local_path): os.remove(final_local_path)
                    os.rename(temp_local_path, final_local_path)
                    if local_filename in (f"{package_id}.apk", "base.apk"): base_local_path = final_local_path

            if base_local_path and os.path.exists(base_local_path):
                self.target_apk = base_local_path
                self.lbl_apk.configure(text=os.path.basename(self.target_apk), text_color="#00E676")
                self.btn_decompile.configure(state="normal")
            self.update_task_state("Application pulled successfully.", "success")
            messagebox.showinfo("Success", f"Application files pulled successfully into directory:\n{app_dir}")
        except Exception as err:
            self.log(f"[-] Pull engine unexpected crash parameter: {str(err)}")
            self.update_task_state("Pull pipeline engine asset failure.", "failed")

    def browse_merge_folder(self):
        folder = filedialog.askdirectory(title="Select Folder Staging Split Chunks")
        if folder:
            self.selected_merge_dir = os.path.normpath(folder)
            self.lbl_merge_dir.configure(text=os.path.basename(self.selected_merge_dir), text_color="#FFFFFF")

    def start_apk_merger(self):
        if not self.selected_merge_dir: return
        self.update_task_state("[APKEditor] Merging bundle components split architecture maps...", "running")
        threading.Thread(target=self.apk_merger_worker, daemon=True).start()

    def apk_merger_worker(self):
        try:
            folder_name = os.path.basename(self.selected_merge_dir)
            parent_dir = os.path.dirname(self.selected_merge_dir)
            final_output_path = os.path.normpath(os.path.join(parent_dir, f"{folder_name}_merged.apk"))
            merge_cmd = ["java", "-jar", "tools/APKEditor.jar", "m", "-i", self.selected_merge_dir, "-o", final_output_path]
            merge_proc = subprocess.Popen(merge_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=SUBPROCESS_FLAGS)
            merge_proc.wait()
            if os.path.exists(final_output_path):
                self.target_apk = final_output_path
                self.lbl_apk.configure(text=os.path.basename(self.target_apk), text_color="#00E676")
                self.btn_decompile.configure(state="normal")
                self.update_task_state("App bundles unified successfully.", "success")
        except Exception : self.update_task_state("APKEditor sub-process engine error.", "failed")

    def start_decompile(self):
        self.btn_decompile.configure(state="disabled")
        self.update_task_state("[Apktool] Decompiling package assets directory structure...", "running")
        output_dir = self.target_apk.replace(".apk", "_decompiled")
        cmd = ["java", "-jar", "tools/apktool.jar", "d", self.target_apk, "-o", output_dir, "-f"]
        threading.Thread(target=self.execute_sub_process, args=(cmd, "Decompilation Task Complete"), daemon=True).start()

    def start_rebuild(self):
        self.btn_decompile.configure(state="disabled"); self.btn_rebuild.configure(state="disabled")
        self.update_task_state("[Apktool] Rebuilding source configurations folder tree...", "running")
        threading.Thread(target=self.rebuild_pipeline_worker, daemon=True).start()

    def start_sign_only(self):
        self.btn_decompile.configure(state="disabled"); self.btn_rebuild.configure(state="disabled"); self.btn_sign_only.configure(state="disabled")
        self.update_task_state("[Apksigner] Executing boundary alignment and cryptographic signatures...", "running")
        threading.Thread(target=self.standalone_sign_pipeline_worker, daemon=True).start()

    def execute_sub_process(self, command_list, terminal_success_msg):
        try:
            process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=SUBPROCESS_FLAGS)
            for line in iter(process.stdout.readline, ''): self.log(line.strip())
            process.stdout.close(); process.wait()
            if process.returncode == 0: self.update_task_state("Operation complete.", "success")
            else: self.update_task_state("Task process execution rejected.", "failed")
        except Exception: self.update_task_state("Infrastructure subprocess system crash.", "failed")
        self.refresh_interface_locks()

    def standalone_sign_pipeline_worker(self):
        base_name = os.path.splitext(self.unsigned_apk_path)[0]
        aligned_apk = f"{base_name}_aligned.apk"
        final_signed_apk = f"{base_name}_SIGNED.apk"
        zipalign_bin = "tools/zipalign" if IS_LINUX else "tools/zipalign.exe"
        subprocess.run([zipalign_bin, "-p", "-f", "4", self.unsigned_apk_path, aligned_apk], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=SUBPROCESS_FLAGS)
        if not os.path.exists(aligned_apk): self.refresh_interface_locks(); return
        cmd_sign = ["java", "-jar", "tools/apksigner.jar", "sign", "--ks", "tools/debug.keystore", "--ks-pass", "pass:android", "--out", final_signed_apk, aligned_apk]
        proc = subprocess.run(cmd_sign, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        if proc.returncode == 0:
            self.update_task_state("Manual package signed successfully.", "success")
            if os.path.exists(aligned_apk): os.remove(aligned_apk)
        self.refresh_interface_locks()

    def rebuild_pipeline_worker(self):
        base_name = os.path.basename(os.path.normpath(self.rebuild_dir))
        output_dir_path = os.path.dirname(os.path.normpath(self.rebuild_dir))
        unsigned_apk = os.path.join(output_dir_path, f"{base_name}_unsigned.apk")
        aligned_apk = os.path.join(output_dir_path, f"{base_name}_MODDED.apk")
        subprocess.run(["java", "-jar", "tools/apktool.jar", "b", self.rebuild_dir, "-o", unsigned_apk], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=SUBPROCESS_FLAGS)
        if not os.path.exists(unsigned_apk): self.refresh_interface_locks(); return
        zipalign_bin = "tools/zipalign" if IS_LINUX else "tools/zipalign.exe"
        subprocess.run([zipalign_bin, "-p", "-f", "4", unsigned_apk, aligned_apk], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=SUBPROCESS_FLAGS)
        cmd_sign = ["java", "-jar", "tools/apksigner.jar", "sign", "--ks", "tools/debug.keystore", "--ks-pass", "pass:android", aligned_apk]
        proc = subprocess.run(cmd_sign, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        if proc.returncode == 0:
            self.update_task_state("Modded bundle recompiled and signed.", "success")
            if os.path.exists(unsigned_apk): os.remove(unsigned_apk)
        self.refresh_interface_locks()

    def start_ios_app_fetch(self):
        if not paramiko: return
        self.btn_fetch_apps.configure(state="disabled")
        self.update_task_state("[SSH] Auditing remote container directory spaces...", "running")
        threading.Thread(target=self.ios_fetch_apps_worker, daemon=True).start()

    def ios_fetch_apps_worker(self):
        ip = self.ent_ios_ip.get().strip(); user = self.ent_ios_user.get().strip(); password = self.ent_ios_pass.get()
        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, username=user, password=password, timeout=10)
            cmd = (
                r'cd /var/containers/Bundle/Application/ && '
                r'for d in *; do '
                r'  if [ -d "$d" ]; then '
                r'    app=$(basename "$(ls -d "$d"/*.app 2>/dev/null | head -n 1)"); '
                r'    if [ ! -z "$app" ]; then '
                r'      name=$(/usr/libexec/PlistBuddy -c "Print CFBundleDisplayName" "$d/$app/Info.plist" 2>/dev/null); '
                r'      if [ -z "$name" ]; then name=$(/usr/libexec/PlistBuddy -c "Print CFBundleName" "$d/$app/Info.plist" 2>/dev/null); fi; '
                r'      if [ -z "$name" ]; then name=$(echo "$app" | sed "s/\.app//"); fi; '
                r'      echo "MATCH|$name|$d|$app"; '
                r'    fi; '
                r'  fi; '
                r'done'
            )
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode("utf-8")
            self.discovered_ios_apps.clear(); app_names = []
            for line in output.splitlines():
                if "MATCH|" in line:
                    parts = line.split("|")
                    if len(parts) == 4:
                        _, app_name, uuid, app_folder = parts
                        sanitized_app_name = app_name.strip().replace('\\', '')
                        sanitized_folder = app_folder.strip().replace('\\', '')
                        self.discovered_ios_apps[sanitized_app_name] = (uuid.strip(), sanitized_folder)
                        app_names.append(sanitized_app_name)
            if app_names:
                self.cbo_ios_apps.configure(values=sorted(app_names))
                self.cbo_ios_apps.set(sorted(app_names)[0])
                self.update_task_state("iOS App bundles decrypted database synced.", "success")
        except Exception: self.update_task_state("SSH Authentication handshake failed.", "failed")
        finally: ssh.close(); self.btn_fetch_apps.configure(state="normal")

    def ios_browse_dest(self):
        folder = filedialog.askdirectory(title="Choose Local Destination Workspace Folder")
        if folder:
            self.ios_dest_dir = folder
            self.lbl_ios_dest.configure(text=os.path.basename(self.ios_dest_dir), text_color="#FFFFFF")

    def start_ipa_build(self):
        selected_app = self.cbo_ios_apps.get()
        if not selected_app or "Scan" in selected_app: return
        if not self.ios_dest_dir: return
        self.btn_build_ipa.configure(state="disabled")
        self.update_task_state(f"[SCP] Pulling and forging local compliance .ipa for {selected_app}...", "running")
        threading.Thread(target=self.ios_ipa_build_worker, args=(selected_app,), daemon=True).start()

    def ios_ipa_build_worker(self, app_name):
        ip = self.ent_ios_ip.get().strip(); user = self.ent_ios_user.get().strip(); password = self.ent_ios_pass.get()
        app_uuid, app_folder_name = self.discovered_ios_apps[app_name]
        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, username=user, password=password)
            remote_app_path = f"/var/containers/Bundle/Application/{app_uuid}/{app_folder_name}"
            base_temp_dir = os.path.abspath(os.path.join(self.ios_dest_dir, "ios_temp"))
            payload_dir = os.path.join(base_temp_dir, "Payload")
            if os.path.exists(base_temp_dir): shutil.rmtree(base_temp_dir)
            os.makedirs(payload_dir, exist_ok=True)

            target_scp_dir = payload_dir
            if sys.platform == "win32" and not target_scp_dir.startswith("\\\\?\\"):
                target_scp_dir = "\\\\?\\" + target_scp_dir.replace("/", "\\")

            self.log(f"[*] Copying payload assets recursively down to tracking location:\n -> {target_scp_dir}")
            with SCPClient(ssh.get_transport()) as scp:
                scp.get(remote_app_path, local_path=target_scp_dir, recursive=True)

            safe_filename = "".join(c for c in app_name if c.isalnum() or c in (" ", "_", "-")).strip()
            ipa_output_path = os.path.abspath(os.path.join(self.ios_dest_dir, f"{safe_filename}.ipa"))

            with zipfile.ZipFile(ipa_output_path, "w", zipfile.ZIP_DEFLATED) as ipa_zip:
                for root, dirs, files in os.walk(base_temp_dir):
                    for file in files:
                        full_fp = os.path.join(root, file)
                        ipa_zip.write(full_fp, os.path.relpath(full_fp, base_temp_dir))

            shutil.rmtree(base_temp_dir)
            self.log(f"\n--- SUCCESS! Final Production IPA Package Forged ---\n -> {ipa_output_path}")
            self.update_task_state("Decrypted IPA compiled successfully.", "success")
            messagebox.showinfo("Success", f"IPA built successfully:\n{ipa_output_path}")
        except Exception as e:
            self.log(f"[-] Packaging workflow runtime fault exception trace: {str(e)}")
            self.update_task_state("Secure transport copy block sequence failure.", "failed")
        finally: ssh.close(); self.btn_build_ipa.configure(state="normal")

    # ---------------------------------------------------------------------
    # BUG BOUNTY RECON DECK — MANIFEST / ENDPOINT / SCOPE LOGIC
    # ---------------------------------------------------------------------
    def _android_attr(self, element, attr_name):
        return element.get(f"{{{ANDROID_NS}}}{attr_name}")

    def parse_android_manifest(self, manifest_path):
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package_name = root.get("package", "")

        app_node = root.find("application")
        app_flags = {"debuggable": None, "allowBackup": None,
                     "usesCleartextTraffic": None, "networkSecurityConfig": False}
        if app_node is not None:
            app_flags["debuggable"] = self._android_attr(app_node, "debuggable")
            app_flags["allowBackup"] = self._android_attr(app_node, "allowBackup")
            app_flags["usesCleartextTraffic"] = self._android_attr(app_node, "usesCleartextTraffic")
            app_flags["networkSecurityConfig"] = self._android_attr(app_node, "networkSecurityConfig") is not None

        permissions = []
        for perm_node in root.findall("uses-permission"):
            name = self._android_attr(perm_node, "name") or ""
            short_name = name.split(".")[-1]
            permissions.append({"name": name, "dangerous": short_name in DANGEROUS_PERMISSIONS})
        dangerous_permissions = [p for p in permissions if p["dangerous"]]

        exported_components = []
        implicit_exported_components = []
        deep_links = []
        component_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
        if app_node is not None:
            for tag in component_tags:
                for comp_node in app_node.findall(tag):
                    comp_name = self._android_attr(comp_node, "name") or "(unnamed)"
                    exported_attr = self._android_attr(comp_node, "exported")
                    intent_filters = comp_node.findall("intent-filter")

                    if exported_attr == "true":
                        exported_components.append({"type": tag, "name": comp_name})
                    elif exported_attr is None and intent_filters:
                        # No explicit android:exported but has an intent-filter: on
                        # targetSdkVersion < 31 this is IMPLICITLY exported by the OS.
                        # Flagged as a warning, not asserted as a confirmed export.
                        implicit_exported_components.append({"type": tag, "name": comp_name})

                    for intent_filter in intent_filters:
                        for data_node in intent_filter.findall("data"):
                            scheme = self._android_attr(data_node, "scheme")
                            host = self._android_attr(data_node, "host")
                            path_prefix = self._android_attr(data_node, "pathPrefix")
                            if scheme or host:
                                deep_links.append({"component": comp_name, "scheme": scheme,
                                                    "host": host, "pathPrefix": path_prefix})

        return {
            "package": package_name,
            "app_flags": app_flags,
            "permissions": permissions,
            "dangerous_permissions": dangerous_permissions,
            "exported_components": exported_components,
            "implicit_exported_components": implicit_exported_components,
            "deep_links": deep_links,
        }

    def start_signature_analysis(self):
        if not self.target_apk:
            messagebox.showwarning("No Target APK", "Load a target APK first (Android tab, ADB pull, or merge).")
            return
        self.btn_analyze_signature.configure(state="disabled")
        self.update_task_state("[Recon] Analyzing APK signature and hashes...", "running")
        threading.Thread(target=self.signature_analysis_worker, daemon=True).start()

    def signature_analysis_worker(self):
        try:
            apk_path = self.target_apk
            self.log(f"\n[*] Analyzing signature & hashes for: {apk_path}")

            hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
            with open(apk_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    for h in hashes.values():
                        h.update(chunk)

            info = {
                "apk_path": apk_path,
                "md5": hashes["md5"].hexdigest(),
                "sha1": hashes["sha1"].hexdigest(),
                "sha256": hashes["sha256"].hexdigest(),
                "v1_verified": None, "v2_verified": None, "v3_verified": None, "v4_verified": None,
                "signer_dn": "", "is_debug_cert": False,
            }

            cmd = ["java", "-jar", "tools/apksigner.jar", "verify", "--print-certs", "-v", apk_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            output = proc.stdout + proc.stderr
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Verified using v1 scheme"):
                    info["v1_verified"] = "true" in line.lower()
                elif line.startswith("Verified using v2 scheme"):
                    info["v2_verified"] = "true" in line.lower()
                elif line.startswith("Verified using v3 scheme"):
                    info["v3_verified"] = "true" in line.lower()
                elif line.startswith("Verified using v4 scheme"):
                    info["v4_verified"] = "true" in line.lower()
                elif "certificate DN:" in line:
                    info["signer_dn"] = line.split("certificate DN:", 1)[-1].strip()

            if info["signer_dn"].replace(" ", "").lower() == ANDROID_DEBUG_CERT_DN.replace(" ", "").lower():
                info["is_debug_cert"] = True

            self.recon_signature_info = info
            self.log(f"[+] MD5={info['md5']} SHA1={info['sha1']} SHA256={info['sha256']}")
            self.log(f"[+] v1={info['v1_verified']} v2={info['v2_verified']} v3={info['v3_verified']} v4={info['v4_verified']} DN={info['signer_dn']}")
            if info["is_debug_cert"]:
                self.log("[!] WARNING: signed with the well-known Android debug certificate.")

            summary = f"v1={info['v1_verified']} v2={info['v2_verified']} v3={info['v3_verified']} | SHA256={info['sha256'][:16]}..."
            if info["is_debug_cert"]:
                summary += " | DEBUG CERT"
            self.lbl_signature_summary.configure(text=summary, text_color="#FF8A65" if info["is_debug_cert"] else "#FFFFFF")
            self.refresh_recon_results_display()
            self.update_task_state("Signature & hash analysis complete.", "success")
        except Exception as e:
            self.log(f"[-] Signature analysis exception: {str(e)}")
            self.update_task_state("Signature analysis failed.", "failed")
        self.btn_analyze_signature.configure(state="normal")

    def start_manifest_extraction(self):
        if not self.recon_target_dir: return
        self.btn_extract_manifest.configure(state="disabled")
        self.update_task_state("[Recon] Parsing AndroidManifest.xml attack surface...", "running")
        threading.Thread(target=self.manifest_extraction_worker, daemon=True).start()

    def manifest_extraction_worker(self):
        try:
            manifest_path = os.path.join(self.recon_target_dir, "AndroidManifest.xml")
            if not os.path.exists(manifest_path):
                self.log(f"[-] AndroidManifest.xml not found at: {manifest_path}")
                self.update_task_state("Manifest file missing.", "failed")
                self.btn_extract_manifest.configure(state="normal")
                return
            self.log(f"\n[*] Parsing manifest: {manifest_path}")
            self.recon_manifest_info = self.parse_android_manifest(manifest_path)
            info = self.recon_manifest_info
            self.log(f"[+] package={info['package']}  dangerous_perms={len(info['dangerous_permissions'])}  "
                      f"exported={len(info['exported_components'])}  implicit_exported={len(info['implicit_exported_components'])}  "
                      f"deep_links={len(info['deep_links'])}")
            self.lbl_manifest_summary.configure(
                text=f"pkg={info['package']} | {len(info['dangerous_permissions'])} dangerous perms | "
                     f"{len(info['exported_components'])} exported | {len(info['implicit_exported_components'])} implicit-exported",
                text_color="#FFFFFF")
            self.refresh_recon_results_display()
            self.update_task_state("Manifest attack surface extracted.", "success")
        except Exception as e:
            self.log(f"[-] Manifest parser exception: {str(e)}")
            self.update_task_state("Manifest parsing failed.", "failed")
        self.btn_extract_manifest.configure(state="normal")

    def start_source_scan(self):
        if not self.recon_target_dir: return
        self.btn_scan_source.configure(state="disabled")
        self.update_task_state("[Recon] Scanning decompiled source for endpoints & secrets...", "running")
        threading.Thread(target=self.source_scan_worker, daemon=True).start()

    def source_scan_worker(self):
        try:
            self.recon_findings = {"urls": set(), "ips": set(), "secrets": [], "code_vulns": []}
            scanned_files = 0
            skipped_large = 0

            for root_dir, dirs, files in os.walk(self.recon_target_dir):
                base = os.path.basename(root_dir).lower()
                if any(base.startswith(p) for p in RECON_SKIP_DIR_PREFIXES):
                    dirs[:] = []
                    continue
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in RECON_TEXT_EXTENSIONS:
                        continue
                    fpath = os.path.join(root_dir, fname)
                    try:
                        if os.path.getsize(fpath) > RECON_MAX_FILE_SIZE:
                            skipped_large += 1
                            continue
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                    except Exception:
                        continue

                    scanned_files += 1
                    for m in URL_PATTERN.finditer(content):
                        self.recon_findings["urls"].add(m.group(0).rstrip(".,;)\"'"))
                    for m in IPV4_PATTERN.finditer(content):
                        self.recon_findings["ips"].add(m.group(0))
                    for secret_type, pattern in SECRET_PATTERNS.items():
                        for m in pattern.finditer(content):
                            matched_value = m.group(1) if m.groups() else m.group(0)
                            self.recon_findings["secrets"].append({
                                "type": secret_type, "match": matched_value,
                                "file": os.path.relpath(fpath, self.recon_target_dir),
                            })
                    for vuln_type, rule in CODE_VULN_PATTERNS.items():
                        if rule["pattern"].search(content):
                            self.recon_findings["code_vulns"].append({
                                "type": vuln_type, "severity": rule["severity"],
                                "file": os.path.relpath(fpath, self.recon_target_dir),
                            })
                    if scanned_files % 200 == 0:
                        self.log(f"[*] Scanned {scanned_files} files so far...")

            deduped = {}
            for s in self.recon_findings["secrets"]:
                key = (s["type"], s["match"])
                if key not in deduped:
                    deduped[key] = s
            self.recon_findings["secrets"] = list(deduped.values())

            deduped_vulns = {}
            for v in self.recon_findings["code_vulns"]:
                key = (v["type"], v["file"])
                if key not in deduped_vulns:
                    deduped_vulns[key] = v
            self.recon_findings["code_vulns"] = list(deduped_vulns.values())

            self.log(f"\n[+] Source scan complete: {scanned_files} files scanned, {skipped_large} skipped (>2MB).")
            self.log(f"[+] {len(self.recon_findings['urls'])} unique URLs, "
                      f"{len(self.recon_findings['ips'])} unique IPs, "
                      f"{len(self.recon_findings['secrets'])} unique secret matches, "
                      f"{len(self.recon_findings['code_vulns'])} code vulnerability findings.")
            self.lbl_scan_summary.configure(
                text=f"{scanned_files} files | {len(self.recon_findings['urls'])} URLs | "
                     f"{len(self.recon_findings['ips'])} IPs | {len(self.recon_findings['secrets'])} secrets | "
                     f"{len(self.recon_findings['code_vulns'])} code vulns",
                text_color="#FFFFFF")
            self.refresh_recon_results_display()
            self.update_task_state("Endpoint & secret extraction complete.", "success")
        except Exception as e:
            self.log(f"[-] Source scan exception: {str(e)}")
            self.update_task_state("Source scan failed.", "failed")
        self.btn_scan_source.configure(state="normal")

    def start_scope_match(self):
        threading.Thread(target=self.scope_match_worker, daemon=True).start()

    def scope_match_worker(self):
        try:
            raw_lines = self.txt_scope.get("1.0", "end").splitlines()
            scope_patterns = [line.strip().lower() for line in raw_lines if line.strip()]
            self.recon_scope_list = scope_patterns

            in_scope, out_scope = [], []
            for url in sorted(self.recon_findings["urls"]):
                host = (urllib.parse.urlparse(url).hostname or "").lower()
                if self._host_matches_scope(host, scope_patterns):
                    in_scope.append(url)
                else:
                    out_scope.append(url)

            self.recon_scope_results = {"in_scope": in_scope, "out_of_scope": out_scope}
            self.log(f"\n[*] Scope match: {len(in_scope)} in-scope URLs, {len(out_scope)} out-of-scope URLs.")
            self.refresh_recon_results_display()
            self.update_task_state("Scope matching complete.", "success")
        except Exception as e:
            self.log(f"[-] Scope matcher exception: {str(e)}")
            self.update_task_state("Scope matching failed.", "failed")

    def _host_matches_scope(self, host, scope_patterns):
        if not host:
            return False
        for pattern in scope_patterns:
            if pattern.startswith("*."):
                suffix = pattern[1:]
                bare = pattern[2:]
                if host == bare or host.endswith(suffix):
                    return True
            elif host == pattern:
                return True
        return False

    def refresh_recon_results_display(self):
        report_text = self.build_recon_report_text()
        self.recon_results_box.delete("1.0", "end")
        self.recon_results_box.insert("1.0", report_text)

    def build_recon_report_text(self):
        lines = ["# Bug Bounty Recon Report",
                 f"Target folder: {self.recon_target_dir or '(none selected)'}", ""]

        if self.recon_manifest_info:
            info = self.recon_manifest_info
            flags = info["app_flags"]
            lines += [
                "## Manifest Attack Surface",
                f"- Package: `{info['package']}`",
                f"- debuggable: {flags.get('debuggable')}",
                f"- allowBackup: {flags.get('allowBackup')}",
                f"- usesCleartextTraffic: {flags.get('usesCleartextTraffic')}",
                f"- networkSecurityConfig present: {flags.get('networkSecurityConfig')}",
                "",
                f"### Dangerous Permissions ({len(info['dangerous_permissions'])})",
            ]
            lines += [f"- {p['name']}" for p in info["dangerous_permissions"]]
            lines += ["", f"### Explicitly Exported Components ({len(info['exported_components'])})"]
            lines += [f"- [{c['type']}] {c['name']}" for c in info["exported_components"]]
            lines += ["", f"### WARNING: Implicit-Exported Components (has intent-filter, no explicit android:exported) "
                            f"({len(info['implicit_exported_components'])})"]
            lines += [f"- [{c['type']}] {c['name']}" for c in info["implicit_exported_components"]]
            lines += ["", f"### Deep Links ({len(info['deep_links'])})"]
            lines += [f"- {dl['component']}: scheme={dl['scheme']} host={dl['host']} pathPrefix={dl['pathPrefix']}"
                      for dl in info["deep_links"]]
            lines.append("")

        if self.recon_findings["urls"] or self.recon_findings["ips"] or self.recon_findings["secrets"]:
            lines.append("## Endpoints & Secrets")
            lines.append(f"### URLs ({len(self.recon_findings['urls'])})")
            lines += [f"- {u}" for u in sorted(self.recon_findings["urls"])]
            lines += ["", f"### IP Addresses ({len(self.recon_findings['ips'])})"]
            lines += [f"- {ip}" for ip in sorted(self.recon_findings["ips"])]
            lines += ["", f"### Potential Secrets ({len(self.recon_findings['secrets'])})"]
            lines += [f"- [{s['type']}] `{s['match']}` (in {s['file']})" for s in self.recon_findings["secrets"]]
            lines.append("")

        if self.recon_findings.get("code_vulns"):
            lines.append(f"## Code Vulnerabilities ({len(self.recon_findings['code_vulns'])})")
            lines += [f"- [{v['severity'].upper()}] {v['type']} (in {v['file']})" for v in self.recon_findings["code_vulns"]]
            lines.append("")

        if self.recon_signature_info:
            sig = self.recon_signature_info
            lines.append("## APK Signature & Hashes")
            lines += [
                f"- File: `{sig.get('apk_path', '')}`",
                f"- MD5: `{sig.get('md5', '')}`",
                f"- SHA1: `{sig.get('sha1', '')}`",
                f"- SHA256: `{sig.get('sha256', '')}`",
                f"- v1 (JAR) scheme verified: {sig.get('v1_verified')}",
                f"- v2 scheme verified: {sig.get('v2_verified')}",
                f"- v3 scheme verified: {sig.get('v3_verified')}",
                f"- v4 scheme verified: {sig.get('v4_verified')}",
                f"- Signer certificate DN: {sig.get('signer_dn', '')}",
            ]
            if sig.get("is_debug_cert"):
                lines.append("- WARNING: signed with the well-known Android debug certificate - not production-safe.")
            lines.append("")

        if self.recon_scope_results["in_scope"] or self.recon_scope_results["out_of_scope"]:
            lines.append("## Scope Match Results")
            lines.append(f"### In-Scope ({len(self.recon_scope_results['in_scope'])})")
            lines += [f"- {u}" for u in self.recon_scope_results["in_scope"]]
            lines += ["", f"### Out-of-Scope / Informational ({len(self.recon_scope_results['out_of_scope'])})"]
            lines += [f"- {u}" for u in self.recon_scope_results["out_of_scope"]]

        return "\n".join(lines)

    def export_recon_report(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".md",
                                                 filetypes=[("Markdown", "*.md"), ("Text", "*.txt")])
        if not filepath:
            return
        try:
            report_text = self.build_recon_report_text()
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(report_text)
            self.log(f"\n[+] Recon report exported to: {filepath}")
            self.update_task_state("Recon report exported.", "success")
            messagebox.showinfo("Success", f"Report exported successfully:\n{filepath}")
        except Exception as e:
            self.log(f"[-] Report export failed: {str(e)}")
            self.update_task_state("Report export failed.", "failed")

    # ---------------------------------------------------------------------
    # DYNAMIC TESTING DECK — DEVICE / FRIDA SERVER PROVISIONING
    # ---------------------------------------------------------------------
    def start_device_detection(self):
        self.update_task_state("[Dynamic] Detecting device environment...", "running")
        threading.Thread(target=self.device_detection_worker, daemon=True).start()

    def device_detection_worker(self):
        try:
            abi_proc = subprocess.run(["adb", "shell", "getprop", "ro.product.cpu.abi"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            abi = abi_proc.stdout.strip()
            ver_proc = subprocess.run(["adb", "shell", "getprop", "ro.build.version.release"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            android_version = ver_proc.stdout.strip()
            if not abi:
                self.log("[-] Could not detect device ABI. Is a device/emulator connected?")
                self.lbl_device_env.configure(text="No device detected.", text_color="#FF1744")
                self.update_task_state("Device detection failed.", "failed")
                return

            self.device_abi = abi
            su_proc = subprocess.run(["adb", "shell", "su", "-c", "id"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            su_output = (su_proc.stdout + su_proc.stderr).strip()
            self.device_root_ready = "uid=0" in su_output

            if self.device_root_ready:
                root_status = "root granted"
                text_color = "#00E676"
            elif "permission denied" in su_output.lower():
                root_status = "su DENIED - open Magisk on the device and grant ADB shell superuser access, then re-detect"
                text_color = "#FF1744"
            else:
                root_status = "su not available (no root)"
                text_color = "#FF1744"

            serial_proc = subprocess.run(["adb", "get-serialno"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            serial = serial_proc.stdout.strip()

            self.log(f"\n[*] Device environment: serial={serial} ABI={abi} Android={android_version} su={su_output!r}")
            self.lbl_device_env.configure(text=f"ABI={abi} | Android {android_version} | {root_status}", text_color=text_color)
            self.update_task_state("Device environment detected.", "success" if self.device_root_ready else "failed")
        except Exception as e:
            self.log(f"[-] Device detection exception: {str(e)}")
            self.update_task_state("Device detection failed.", "failed")

    def start_frida_server_deploy(self):
        if frida is None:
            messagebox.showerror("Frida Missing", "The 'frida' Python package is not installed. Install it via the Settings tab or 'pip install frida'.")
            return
        self.btn_deploy_frida.configure(state="disabled")
        self.update_task_state("[Frida] Deploying frida-server to device...", "running")
        threading.Thread(target=self.frida_server_deploy_worker, daemon=True).start()

    def frida_server_deploy_worker(self):
        arch_map = {"x86_64": "x86_64", "x86": "x86", "arm64-v8a": "arm64", "armeabi-v7a": "arm", "armeabi": "arm"}
        try:
            abi_proc = subprocess.run(["adb", "shell", "getprop", "ro.product.cpu.abi"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            abi = abi_proc.stdout.strip()
            arch = arch_map.get(abi)
            if not arch:
                self.log(f"[-] Unsupported/unknown device ABI: {abi}")
                self.update_task_state("Frida deploy failed - unknown ABI.", "failed")
                self.btn_deploy_frida.configure(state="normal")
                return

            version = frida.__version__
            os.makedirs(FRIDA_SERVER_CACHE_DIR, exist_ok=True)
            xz_name = f"frida-server-{version}-android-{arch}.xz"
            xz_path = os.path.join(FRIDA_SERVER_CACHE_DIR, xz_name)
            bin_path = os.path.join(FRIDA_SERVER_CACHE_DIR, f"frida-server-{version}-android-{arch}")

            if not os.path.exists(bin_path):
                if not os.path.exists(xz_path):
                    url = FRIDA_SERVER_RELEASE_URL_TMPL.format(version=version, arch=arch)
                    self.log(f"\n[*] Downloading frida-server: {url}")
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req) as response, open(xz_path, 'wb') as out_file:
                        shutil.copyfileobj(response, out_file)
                self.log("[*] Decompressing frida-server...")
                with lzma.open(xz_path, "rb") as compressed, open(bin_path, "wb") as out_file:
                    shutil.copyfileobj(compressed, out_file)

            self.log(f"[*] Pushing frida-server to device: {FRIDA_SERVER_REMOTE_PATH}")
            push_proc = subprocess.run(["adb", "push", bin_path, FRIDA_SERVER_REMOTE_PATH], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            if push_proc.returncode != 0:
                self.log(f"[-] Push failed: {push_proc.stderr}")
                self.update_task_state("Frida deploy failed - push error.", "failed")
                self.btn_deploy_frida.configure(state="normal")
                return

            subprocess.run(["adb", "shell", "chmod", "755", FRIDA_SERVER_REMOTE_PATH], creationflags=SUBPROCESS_FLAGS)

            su_check = subprocess.run(["adb", "shell", "su", "-c", "id"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            su_output = (su_check.stdout + su_check.stderr).strip()
            if "uid=0" not in su_output:
                self.log(f"[-] su access denied ({su_output!r}). Open Magisk on the device and grant ADB shell superuser access, then retry.")
                self.lbl_frida_server_status.configure(text="su denied - grant Magisk ADB access first.", text_color="#FF1744")
                self.update_task_state("Frida deploy failed - su denied.", "failed")
                self.btn_deploy_frida.configure(state="normal")
                return
            self.device_root_ready = True

            subprocess.run(["adb", "shell", "pkill", "frida-server"], capture_output=True, creationflags=SUBPROCESS_FLAGS)
            self.frida_server_process = subprocess.Popen(
                ["adb", "shell", "su", "-c", FRIDA_SERVER_REMOTE_PATH],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=SUBPROCESS_FLAGS
            )
            time.sleep(1.5)
            if self.frida_server_process.poll() is not None:
                output = self.frida_server_process.stdout.read()
                self.log(f"[-] frida-server exited immediately: {output.strip()}")
                self.lbl_frida_server_status.configure(text="frida-server failed to start.", text_color="#FF1744")
                self.update_task_state("Frida deploy failed.", "failed")
                self.btn_deploy_frida.configure(state="normal")
                return

            subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"], creationflags=SUBPROCESS_FLAGS)
            self.log(f"\n[+] frida-server {version} ({arch}) deployed and running on device.")
            self.lbl_frida_server_status.configure(text=f"frida-server {version} running.", text_color="#00E676")
            self.update_task_state("Frida server deployed.", "success")
        except Exception as e:
            self.log(f"[-] Frida server deploy exception: {str(e)}")
            self.update_task_state("Frida deploy failed.", "failed")
        self.btn_deploy_frida.configure(state="normal")

    # ---------------------------------------------------------------------
    # DYNAMIC TESTING DECK — TARGET APP SCAN + BYPASS SCRIPT RUNNER
    # ---------------------------------------------------------------------
    def start_dynamic_app_scan(self):
        self.update_task_state("[ADB] Querying installed packages for dynamic testing...", "running")
        threading.Thread(target=self.dynamic_app_scan_worker, daemon=True).start()

    def dynamic_app_scan_worker(self):
        try:
            cmd = ["adb", "shell", "pm", "list", "packages", "-3"]
            process = subprocess.run(cmd, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            if process.returncode != 0:
                self.update_task_state("ADB Interface Link dropped.", "failed"); return
            self.discovered_dynamic_apps.clear()
            dropdown_entries = []
            raw_packages = [line.replace("package:", "").strip() for line in process.stdout.splitlines() if line.startswith("package:")]
            if not raw_packages: return

            for pkg in sorted(raw_packages):
                info_cmd = f"adb shell \"dumpsys package {pkg} | grep -i 'label=' | head -n 1\""
                info_proc = subprocess.run(info_cmd, capture_output=True, text=True, shell=True, creationflags=SUBPROCESS_FLAGS)
                raw_info = info_proc.stdout.strip()
                app_label = raw_info.split("label=")[-1].strip().replace("'", "").replace('"', '') if "label=" in raw_info else pkg.split(".")[-1].capitalize()
                display_string = f"{app_label} ({pkg})"
                self.discovered_dynamic_apps[display_string] = (pkg, app_label)
                dropdown_entries.append(display_string)

            self.cbo_dynamic_apps.configure(values=dropdown_entries)
            self.cbo_dynamic_apps.set(dropdown_entries[0])
            self.update_task_state("Installed app list synced.", "success")
        except Exception:
            self.update_task_state("ADB Parser unexpected crash.", "failed")

    def start_bypass_script(self, mode):
        if frida is None:
            messagebox.showerror("Frida Missing", "The 'frida' Python package is not installed.")
            return
        if mode == "custom" and not self.custom_frida_script_path:
            messagebox.showwarning("No Custom Script", "Load a custom Frida script first.")
            return
        selected_display = self.cbo_dynamic_apps.get()
        if not selected_display or "Scan" in selected_display:
            messagebox.showwarning("No Target", "Scan and select a target app first.")
            return
        self.dynamic_target_package = self.discovered_dynamic_apps[selected_display][0]
        self.update_task_state(f"[Frida] Attaching to {self.dynamic_target_package}...", "running")
        threading.Thread(target=self.bypass_script_worker, args=(mode,), daemon=True).start()

    def bypass_script_worker(self, mode):
        try:
            subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"], capture_output=True, creationflags=SUBPROCESS_FLAGS)
            device = frida.get_remote_device()
            self.frida_device = device
            self.log(f"\n[*] Connected to Frida device: {device.name}")

            try:
                session = device.attach(self.dynamic_target_package)
                self.log(f"[*] Attached to running process: {self.dynamic_target_package}")
            except frida.ProcessNotFoundError:
                pid = device.spawn(self.dynamic_target_package)
                session = device.attach(pid)
                device.resume(pid)
                self.log(f"[*] Spawned and attached to: {self.dynamic_target_package} (pid={pid})")

            self.frida_session = session

            script_paths = []
            if mode in ("ssl", "both"):
                script_paths.append(("SSL Pinning Bypass", SSL_PINNING_BYPASS_SCRIPT))
            if mode in ("root", "both"):
                script_paths.append(("Root Detection Bypass", ROOT_DETECTION_BYPASS_SCRIPT))
            if mode == "custom":
                script_paths.append((os.path.basename(self.custom_frida_script_path), self.custom_frida_script_path))

            combined_source = ""
            for label, path in script_paths:
                with open(path, "r", encoding="utf-8") as fh:
                    combined_source += fh.read() + "\n"

            script = session.create_script(combined_source)
            script.on("message", self._on_frida_message)
            script.load()
            self.frida_script = script

            loaded_labels = ", ".join(l for l, _ in script_paths)
            self.dynamic_results_box.insert("end", f"[+] Loaded: {loaded_labels} against {self.dynamic_target_package}\n")
            self.dynamic_results_box.see("end")
            self.update_task_state("Bypass script(s) loaded and running.", "success")
        except Exception as e:
            self.log(f"[-] Frida bypass exception: {str(e)}")
            self.update_task_state("Frida bypass failed.", "failed")

    def _on_frida_message(self, message, data):
        if message["type"] == "send":
            text = message["payload"]
        elif message["type"] == "error":
            text = f"ERROR: {message.get('stack', message.get('description', message))}"
        else:
            text = str(message)
        self.log(f"[Frida] {text}")
        self.dynamic_results_box.insert("end", f"{text}\n")
        self.dynamic_results_box.see("end")

    def browse_custom_frida_script(self):
        filepath = filedialog.askopenfilename(title="Select Custom Frida Script", filetypes=[("Frida JS", "*.js")])
        if filepath:
            self.custom_frida_script_path = filepath
            self.lbl_custom_script.configure(text=os.path.basename(filepath), text_color="#00E676")
            self.btn_run_custom_bypass.configure(state="normal")

    def stop_dynamic_session(self):
        try:
            if self.frida_script:
                self.frida_script.unload()
                self.frida_script = None
            if self.frida_session:
                self.frida_session.detach()
                self.frida_session = None
            self.log("\n[*] Detached from Frida session.")
            self.update_task_state("Dynamic session detached.", "idle")
        except Exception as e:
            self.log(f"[-] Detach exception: {str(e)}")


if __name__ == "__main__":
    try:
        print("[*] Spawning CustomTkinter Engine Window...")
        main_window = NKCyberSuiteMobile()
        main_window.mainloop()
        print("[+] Window closed cleanly.")
    except Exception as error:
        print(f"\n[-] ENGINE RUNTIME CRASH LOG:\n{error}\n")
