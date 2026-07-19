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

from tools import flutter_ssl_bypass

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
FLUTTER_BYPASS_OUTPUT_DIR = os.path.normpath("frida_scripts/generated")
CAPTURE_TRAFFIC_OUTPUT_DIR = os.path.normpath("frida_scripts/generated")

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
        
        self.title("MobiSuite v1.3.0")
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
        self.lspd_module_apk_path = ""
        self.flutter_bypass_apk_path = ""
        self.flutter_hit_count = 0
        self.flutter_watchdog_timer = None

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

        self.btn_nav_recon = ctk.CTkButton(self.sidebar, text="🎯 Bug Bounty Recon",
                                            fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                            command=lambda: self.switch_deck_context("recon"))
        self.btn_nav_recon.pack(padx=15, pady=5, fill="x")

        self.btn_nav_flutter_bypass = ctk.CTkButton(self.sidebar, text="🦋 Flutter Application Bypass",
                                              fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                              command=lambda: self.switch_deck_context("flutter_bypass"))
        self.btn_nav_flutter_bypass.pack(padx=15, pady=5, fill="x")

        self.btn_nav_native_bypass = ctk.CTkButton(self.sidebar, text="🔒 Native Application Bypass",
                                              fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                              command=lambda: self.switch_deck_context("native_bypass"))
        self.btn_nav_native_bypass.pack(padx=15, pady=5, fill="x")

        self.btn_nav_console = ctk.CTkButton(self.sidebar, text="📟 Live Terminal Logs",
                                            fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                            command=lambda: self.switch_deck_context("console"))
        self.btn_nav_console.pack(padx=15, pady=5, fill="x")

        self.btn_nav_settings = ctk.CTkButton(self.sidebar, text="⚙️ Environment Settings",
                                            fg_color="transparent", hover_color="#3D3F4D", height=40, anchor="w",
                                            command=lambda: self.switch_deck_context("settings"))
        self.btn_nav_settings.pack(padx=15, pady=5, fill="x")

        copyright_lbl = ctk.CTkLabel(self.sidebar, text="© 2026 Nilesh Kale\nAll Rights Reserved\nVersion 1.3.0", font=ctk.CTkFont(size=10), text_color="gray", justify="center")
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
        self.view_native_bypass = ctk.CTkScrollableFrame(self.main_deck, fg_color="transparent", label_text="")
        self.view_flutter_bypass = ctk.CTkScrollableFrame(self.main_deck, fg_color="transparent", label_text="")
        self.view_console = ctk.CTkFrame(self.main_deck, fg_color="transparent")

        # Shared cross-tab state for the Flutter/Native bypass split: one physical Frida
        # server + one physical iptables/Burp-routing state on the device, mirrored into
        # whichever tab(s) display it so nothing gets deployed twice or drifts out of sync.
        self.lbl_device_env_widgets = []
        self.lbl_frida_server_status_widgets = []
        self.lbl_burp_status_widgets = []
        self.burp_results_boxes = []
        self.target_app_combo_widgets = []
        self.frida_attach_results_boxes = []
        self.burp_port_var = tk.StringVar(value="8080")

        self.generate_android_deck_ui()
        self.generate_ios_deck_ui()
        self.generate_settings_deck_ui()
        self.generate_recon_deck_ui()
        self.generate_flutter_bypass_deck_ui()
        self.generate_native_bypass_deck_ui()
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
        self.btn_nav_native_bypass.configure(fg_color="transparent", text_color="#A0A0A5")
        self.btn_nav_flutter_bypass.configure(fg_color="transparent", text_color="#A0A0A5")

        self.view_android.pack_forget()
        self.view_ios.pack_forget()
        self.view_settings.pack_forget()
        self.view_recon.pack_forget()
        self.view_native_bypass.pack_forget()
        self.view_flutter_bypass.pack_forget()
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
        elif target_deck == "native_bypass":
            self.btn_nav_native_bypass.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_native_bypass.pack(fill="both", expand=True, padx=5, pady=5)
        elif target_deck == "flutter_bypass":
            self.btn_nav_flutter_bypass.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_flutter_bypass.pack(fill="both", expand=True, padx=5, pady=5)

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

    # ---------------------------------------------------------------------
    # SHARED CARD BUILDERS — used by BOTH generate_native_bypass_deck_ui() and
    # generate_flutter_bypass_deck_ui() so each tab is fully self-contained (its own
    # target picker + traffic routing) without copy-pasting the same 40 lines twice.
    # ---------------------------------------------------------------------
    def _build_target_selector_card(self, parent):
        """Own 'Target Application' card with its own combo box. Returns the combo widget."""
        card = ctk.CTkFrame(parent, fg_color="#16161A", corner_radius=6)
        card.pack(fill="x", pady=4)
        ctk.CTkLabel(card, text="① Select Target Application", font=ctk.CTkFont(size=12, weight="bold"), text_color="#FFB300").pack(anchor="w", padx=15, pady=(6, 4))
        sub = ctk.CTkFrame(card, fg_color="transparent")
        sub.pack(fill="x", padx=15, pady=(0, 10))
        ctk.CTkButton(sub, text="Scan Installed Apps", width=150, fg_color="#0288D1", hover_color="#039BE5",
                      command=self.start_dynamic_app_scan).pack(side="left", padx=(0, 5))
        combo = ctk.CTkComboBox(sub, values=["Click Scan to look up application lists..."], width=280)
        combo.pack(side="left", padx=5)
        self.target_app_combo_widgets.append(combo)
        return combo

    def _build_frida_server_card(self, parent, owns_deploy):
        """
        Device environment + frida-server status. Only ONE tab should 'own' the actual
        Deploy button (Flutter, since the Flutter bypass mechanism IS Frida) — the other
        tab just displays the same live status via the broadcast lists, owns_deploy=False,
        so the two tabs can never fight over deploying the process twice.
        """
        card = ctk.CTkFrame(parent, fg_color="#16161A", corner_radius=6)
        card.pack(fill="x", pady=4)
        title = "② Device Environment & Frida Server" if owns_deploy else "Frida Server Status (reference — deploy from 🦋 Flutter Application Bypass tab)"
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E5FF").pack(anchor="w", padx=15, pady=(6, 4))

        sub_env = ctk.CTkFrame(card, fg_color="transparent")
        sub_env.pack(fill="x", padx=15, pady=(0, 6))
        if owns_deploy:
            ctk.CTkButton(sub_env, text="Detect Device Environment", width=190, fg_color="#37474F", hover_color="#455A64",
                          command=self.start_device_detection).pack(side="left", padx=(0, 5))
        lbl_env = ctk.CTkLabel(sub_env, text="Device environment not detected yet.", text_color="#A0A0A5", anchor="w")
        lbl_env.pack(side="left", padx=5)
        self.lbl_device_env_widgets.append(lbl_env)

        sub_frida = ctk.CTkFrame(card, fg_color="transparent")
        sub_frida.pack(fill="x", padx=15, pady=(0, 10))
        if owns_deploy:
            self.btn_deploy_frida = ctk.CTkButton(sub_frida, text="Deploy Frida Server", width=190, fg_color="#5E35B1", hover_color="#6F35B1",
                                                    command=self.start_frida_server_deploy)
            self.btn_deploy_frida.pack(side="left", padx=(0, 5))
        lbl_frida = ctk.CTkLabel(sub_frida, text="Frida server not deployed yet.", text_color="#A0A0A5", anchor="w")
        lbl_frida.pack(side="left", padx=5)
        self.lbl_frida_server_status_widgets.append(lbl_frida)

    def _build_traffic_routing_card(self, parent, combo, step_num):
        """
        Traffic routing: the live iptables Enable/Verify/Revert buttons (broad, unscoped —
        good for general recon) PLUS the UID-scoped 'Generate Capture-Traffic Script'
        button (narrow, this-app-only — good for focused capture that won't disturb other
        apps on the phone). Port field is bound to the shared burp_port_var StringVar so
        both tabs' port fields always show the same value without any manual syncing.
        """
        card = ctk.CTkFrame(parent, fg_color="#16161A", corner_radius=6)
        card.pack(fill="x", pady=4)
        ctk.CTkLabel(card, text=f"{step_num} Route Traffic to Burp Suite", font=ctk.CTkFont(size=12, weight="bold"), text_color="#7C4DFF").pack(anchor="w", padx=15, pady=(6, 2))
        ctk.CTkLabel(card,
            text="'Enable Redirect' routes the WHOLE device's port 80/443 traffic to Burp (adb reverse + iptables NAT) — quick "
                 "for general recon. 'Generate Capture-Traffic Script' instead writes a .bat that redirects ONLY the selected "
                 "app's traffic (UID-scoped), so it won't break anything else on the phone — run that .bat directly in cmd.exe, "
                 "any time, including after a reboot. In Burp: Proxy -> Settings -> listener on 127.0.0.1:<port> with "
                 "'Support invisible proxying' enabled.\n"
                 "⚠ IMPORTANT: a redirect rule only catches NEW connections — it does nothing for connections the app already had "
                 "open before you enabled it. If nothing shows up in Burp after enabling, click 'Force-Restart Target App' below "
                 "(or manually force-stop + reopen it) so it makes a fresh connection under the new rule.\n"
                 "⚠ Switching the app dropdown above does NOT set up a redirect by itself — the redirect is tied to whichever app "
                 "you clicked Generate/Enable FOR, not whatever's currently selected. Picking a different app? Click Generate/Enable "
                 "again for it (safe to do — scoped rules stack, testing app #2 doesn't remove app #1's rule). Use 'Show Active "
                 "Capture Rules' below any time to see exactly which app(s) are actually being redirected right now.\n"
                 "⚠ 'Revert (ALL Apps On This Port)' clears EVERY rule on this port — including other apps you set up earlier in "
                 "the same session. If you're testing multiple apps at once, use 'Revert (This App Only)' instead — it only removes "
                 "the currently-selected app's own UID-scoped rule and leaves everyone else's capture running.",
            font=ctk.CTkFont(size=10), text_color="#A0A0A5", anchor="w", justify="left", wraplength=780).pack(anchor="w", padx=15, pady=(0, 6))

        sub_a = ctk.CTkFrame(card, fg_color="transparent")
        sub_a.pack(fill="x", padx=15, pady=(0, 6))
        ctk.CTkLabel(sub_a, text="Burp Port:").pack(side="left", padx=(0, 5))
        ctk.CTkEntry(sub_a, width=80, textvariable=self.burp_port_var).pack(side="left", padx=(0, 15))
        ctk.CTkButton(sub_a, text="Enable Redirect (All Apps)", width=180, fg_color="#5E35B1", hover_color="#6F35B1",
                      command=self.start_burp_redirect_enable).pack(side="left", padx=(0, 5))
        ctk.CTkButton(sub_a, text="Verify Rules", width=120, fg_color="#0288D1", hover_color="#039BE5",
                      command=self.start_burp_redirect_verify).pack(side="left", padx=5)
        ctk.CTkButton(sub_a, text="Revert (ALL Apps On This Port)", width=220, fg_color="#B71C1C", hover_color="#C62828",
                      command=self.start_burp_redirect_revert).pack(side="left", padx=5)

        sub_a2 = ctk.CTkFrame(card, fg_color="transparent")
        sub_a2.pack(fill="x", padx=15, pady=(0, 6))
        ctk.CTkButton(sub_a2, text="Generate Capture-Traffic Script (This App Only)", width=280, fg_color="#00838F", hover_color="#00ACC1",
                      command=lambda: self.start_generate_capture_script(combo)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(sub_a2, text="Revert (This App Only)", width=180, fg_color="#37474F", hover_color="#455A64",
                      command=lambda: self.start_burp_redirect_revert_scoped(combo)).pack(side="left", padx=5)
        ctk.CTkButton(sub_a2, text="Force-Restart Target App", width=200, fg_color="#EF6C00", hover_color="#F57C00",
                      command=lambda: self.start_force_restart_target(combo)).pack(side="left", padx=5)
        ctk.CTkButton(sub_a2, text="Show Active Capture Rules", width=200, fg_color="#37474F", hover_color="#455A64",
                      command=self.start_show_active_rules).pack(side="left", padx=5)

        sub_b = ctk.CTkFrame(card, fg_color="transparent")
        sub_b.pack(fill="x", padx=15, pady=(0, 6))
        lbl_status = ctk.CTkLabel(sub_b, text="Status: not routed yet.", text_color="#A0A0A5", anchor="w")
        lbl_status.pack(side="left")
        self.lbl_burp_status_widgets.append(lbl_status)

        box = ctk.CTkTextbox(card, fg_color="#09090B", text_color="#00E676", font=ctk.CTkFont(family="Consolas", size=12), height=120)
        box.pack(fill="x", padx=15, pady=(0, 12))
        self.burp_results_boxes.append(box)

    # ---------------------------------------------------------------------
    # SHARED — TARGET-APP SELECTION (each tab owns its OWN combo box so Native
    # and Flutter can point at two different apps at once; scanning from either
    # tab refreshes the installed-app list in BOTH, since it's the same phone).
    # ---------------------------------------------------------------------
    def _resolve_selected_target(self, combo, warn=True):
        """
        Reads whatever is currently picked in the given tab's own target combo box and
        returns the resolved package name. Picking an item in a combo box only holds a
        display string, not the real package — this is what turns that string into the
        actual package name every worker needs. Also mirrors the result into
        self.dynamic_target_package for any shared legacy code path that still reads it.
        """
        selected_display = combo.get()
        if not selected_display or "Scan" in selected_display or selected_display not in self.discovered_dynamic_apps:
            if warn:
                messagebox.showwarning("No Target", "Click 'Scan Installed Apps' and select a target app first.")
            return None
        pkg = self.discovered_dynamic_apps[selected_display][0]
        self.dynamic_target_package = pkg
        return pkg

    # ---------------------------------------------------------------------
    # SHARED — STATUS BROADCAST HELPERS
    #
    # Device Frida-server state and the iptables/Burp traffic-routing state are each a
    # SINGLE physical thing on the connected phone — there is only one frida-server
    # process and one iptables table, no matter how many tabs show a status for them.
    # Rather than duplicate the deploy/enable logic per tab (which would let the two
    # tabs' displays drift out of sync, or double-deploy), each of these helpers updates
    # every label/box that has registered itself in the matching *_widgets list, so any
    # tab that just wants to DISPLAY the shared state (without owning the control that
    # changes it) can add its label to the list and it stays live automatically.
    # ---------------------------------------------------------------------
    def _set_device_env_status(self, text, color):
        for w in self.lbl_device_env_widgets:
            if w.winfo_exists():
                w.configure(text=text, text_color=color)

    def _set_frida_status(self, text, color):
        for w in self.lbl_frida_server_status_widgets:
            if w.winfo_exists():
                w.configure(text=text, text_color=color)

    def _set_burp_status(self, text, color):
        for w in self.lbl_burp_status_widgets:
            if w.winfo_exists():
                w.configure(text=text, text_color=color)

    def _dyn_log(self, msg):
        """Broadcasts Frida attach/status output (bypass_script_worker, _on_frida_message)
        to every tab's own console box — Native's Frida-based bypass and Flutter's
        auto-offset bypass both attach through the same shared frida session machinery."""
        for box in self.frida_attach_results_boxes:
            if box.winfo_exists():
                box.insert("end", msg + "\n")
                box.see("end")

    # ---------------------------------------------------------------------
    # SHARED — GENERATE CAPTURE-TRAFFIC .BAT SCRIPT (UID-scoped, native + Flutter alike)
    #
    # Traffic capture setup (adb reverse + IPv6 disable + iptables DNAT) does not care
    # whether the target app is native or Flutter — only the SSL BYPASS mechanism
    # differs between them. Scoping the iptables rule with -m owner --uid-owner <uid>
    # (looked up via an EXACT match on `pm list packages -U`, never a substring match —
    # a sibling package name like "com.example.app.cug" will otherwise silently steal
    # the wrong UID) keeps this from redirecting the whole device's traffic, unlike the
    # broader Step 2 Burp routing buttons above, which stay unscoped on purpose for
    # general recon.
    # ---------------------------------------------------------------------
    def _get_package_uid(self, package, log_fn):
        proc = subprocess.run(["adb", "shell", "pm", "list", "packages", "-U", package],
                               capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        output = (proc.stdout + proc.stderr)
        for line in output.splitlines():
            line = line.strip()
            m = re.match(rf"^package:{re.escape(package)}\s+uid:(\d+)\s*$", line)
            if m:
                return m.group(1)
        log_fn(f"[FAIL] No exact-match UID found for '{package}'. Raw output:\n{output.strip() or '(empty)'}")
        log_fn("[HINT] If this package has a sibling with a similar name (e.g. a '.cug'/'.debug' variant), "
               "make sure the app is actually installed and the package name is spelled exactly right.")
        return None

    def _write_capture_traffic_bat(self, package, uid, port, out_path):
        lines = [
            "@echo off",
            f"REM Auto-generated by MobiSuite-Mobile - capture traffic for {package} (UID {uid}) via Burp on port {port}",
            "REM Re-run this after every device reboot - none of this survives a restart.",
            "echo [*] Forwarding local Burp port back through adb...",
            f"adb reverse tcp:{port} tcp:{port}",
            "echo [*] Disabling IPv6 (redirect below is IPv4-only, IPv6 traffic would otherwise sail past it)...",
            "adb shell su -c \"echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6\"",
            "adb shell su -c \"echo 1 > /proc/sys/net/ipv6/conf/wlan0/disable_ipv6\"",
            f"echo [*] Redirecting {package}'s HTTPS/HTTP traffic (UID {uid} only) to 127.0.0.1:{port}...",
            f"adb shell su -c \"iptables -t nat -A OUTPUT -m owner --uid-owner {uid} -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:{port}\"",
            f"adb shell su -c \"iptables -t nat -A OUTPUT -m owner --uid-owner {uid} -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:{port}\"",
            "echo [*] Verifying the rules actually took effect...",
            "adb shell su -c \"iptables -t nat -L OUTPUT -n --line-numbers\"",
            "echo [*] Force-restarting the app so it opens a FRESH connection under the new rule",
            "echo     (a redirect rule only catches NEW connections, not ones already open before it was added)...",
            f"adb shell am force-stop {package}",
            f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1",
            "echo.",
            "echo Done. In Burp: Proxy -> Settings -> listener on 127.0.0.1:%s with 'Support invisible proxying' enabled." % port,
            "pause",
        ]
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\r\n".join(lines) + "\r\n")

    def start_generate_capture_script(self, combo):
        package = self._resolve_selected_target(combo, warn=True)
        if not package:
            return
        port = self._burp_get_port()
        if not port:
            return
        self.update_task_state(f"[Capture Traffic] Generating .bat for {package}...", "running")
        threading.Thread(target=self._generate_capture_script_worker, args=(package, port), daemon=True).start()

    def _generate_capture_script_worker(self, package, port):
        def log(msg):
            self._burp_log(msg)
            self.log(msg)

        log(f"[*] Looking up UID for {package}...")
        uid = self._get_package_uid(package, log)
        if not uid:
            self.update_task_state("Capture-traffic script generation failed - UID lookup failed.", "failed")
            return
        log(f"[OK] UID: {uid}")

        safe_pkg = re.sub(r"[^A-Za-z0-9._-]", "_", package)
        out_path = os.path.join(CAPTURE_TRAFFIC_OUTPUT_DIR, f"capture_traffic_{safe_pkg}_{port}.bat")
        try:
            self._write_capture_traffic_bat(package, uid, port, out_path)
        except Exception as e:
            log(f"[FAIL] Could not write script: {str(e)}")
            self.update_task_state("Capture-traffic script generation failed.", "failed")
            return

        abs_path = os.path.abspath(out_path)
        log(f"[OK] Script written: {abs_path}")
        log("[*] Run it directly in cmd.exe (double-click, or `cmd /c` it) — no Python/GUI needed. Redo after every device reboot.")
        self.update_task_state(f"Capture-traffic script ready: {os.path.basename(out_path)}", "success")
        messagebox.showinfo("Capture-Traffic Script Generated",
                             f"Written to:\n{abs_path}\n\nRun it in cmd.exe. Re-run after every device reboot "
                             f"(the redirect doesn't persist).")

    # ---------------------------------------------------------------------
    # SHARED — FORCE-RESTART TARGET APP
    #
    # An iptables DNAT rule (whichever kind — broad or UID-scoped) only intercepts NEW
    # outgoing connections; it does nothing for TCP connections the app already had open
    # before the rule was added. If the target app was already running when you enabled
    # the redirect, its existing keep-alive connections keep flowing straight past Burp
    # and it LOOKS like nothing is being captured. Force-stopping and relaunching forces
    # a brand new connection under the new rule — confirmed this is exactly what was
    # needed the first time capture appeared to not be working during testing.
    # ---------------------------------------------------------------------
    def start_force_restart_target(self, combo):
        package = self._resolve_selected_target(combo, warn=True)
        if not package:
            return
        self.update_task_state(f"[Restart] Force-stopping and relaunching {package}...", "running")
        threading.Thread(target=self._force_restart_target_worker, args=(package,), daemon=True).start()

    def _force_restart_target_worker(self, package):
        self._burp_log(f"[*] adb shell am force-stop {package}")
        subprocess.run(["adb", "shell", "am", "force-stop", package], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        time.sleep(1.5)
        self._burp_log(f"[*] Relaunching {package} (fresh process — any traffic it now makes uses a brand new connection, "
                        f"so it actually hits the current iptables rule)...")
        proc = subprocess.run(["adb", "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"],
                               capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        out = (proc.stdout + proc.stderr).strip()
        self._burp_log(out if out else "(no output)")
        if "Events injected: 1" in out:
            self._burp_log(f"[OK] {package} relaunched. Navigate the app to trigger a request, then check Burp -> Proxy -> HTTP history.")
            self.update_task_state(f"{package} force-restarted.", "success")
        else:
            self._burp_log("[WARN] Relaunch may not have worked — check the output above (app may not have a LAUNCHER activity, "
                            "or the package name may be wrong).")
            self.update_task_state(f"{package} restart: unclear result.", "failed")

    # ---------------------------------------------------------------------
    # SHARED — SHOW ACTIVE CAPTURE RULES
    #
    # UID-scoped rules are additive (each 'Generate Capture-Traffic Script' click just
    # appends a new -A rule) — switching the target-app dropdown does NOT itself set up a
    # redirect for the newly selected app, and it does NOT remove the rule for whichever
    # app you set up before. So it's easy to think "I switched apps, why isn't THIS one
    # capturing" when really the old app's rule is still the only one active. This reads
    # the live table and resolves each UID back to a package name so it's obvious which
    # app(s) are actually being redirected right now.
    # ---------------------------------------------------------------------
    def _resolve_pkg_name_from_uid(self, uid):
        proc = subprocess.run(["adb", "shell", "pm", "list", "packages", "-U"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        for line in proc.stdout.splitlines():
            m = re.match(rf"^package:(\S+)\s+uid:{uid}\s*$", line.strip())
            if m:
                return m.group(1)
        return None

    def start_show_active_rules(self):
        self._burp_clear_log()
        self.update_task_state("[Capture Traffic] Listing active per-app redirect rules...", "running")
        threading.Thread(target=self._show_active_rules_worker, daemon=True).start()

    def _show_active_rules_worker(self):
        _, output = self._run_adb_su("iptables -t nat -L OUTPUT -n --line-numbers")
        self._burp_log("---- iptables -t nat -L OUTPUT -n --line-numbers ----")
        self._burp_log(output if output else "(empty)")

        uid_re = re.compile(r"owner UID match (\d+).*?dpt:(\d+)")
        scoped = {}
        unscoped_ports = set()
        for line in output.splitlines():
            if "DNAT" not in line or "to:127.0.0.1" not in line:
                continue
            m = uid_re.search(line)
            if m:
                uid, dport = m.group(1), m.group(2)
                scoped.setdefault(uid, set()).add(dport)
            else:
                dm = re.search(r"dpt:(\d+)", line)
                if dm:
                    unscoped_ports.add(dm.group(1))

        if not scoped and not unscoped_ports:
            self._burp_log("\n[*] No active redirect rules at all right now — nothing is being captured for ANY app.")
            self.update_task_state("No active capture rules.", "idle")
            return

        self._burp_log("\n---- Active per-app capture rules ----")
        if unscoped_ports:
            self._burp_log(f"  ALL APPS (broad, unscoped redirect) — ports {sorted(unscoped_ports, key=int)}")
        for uid, ports in scoped.items():
            pkg_name = self._resolve_pkg_name_from_uid(uid) or "unknown package"
            self._burp_log(f"  {pkg_name} (UID {uid}) — ports {sorted(ports, key=int)}")
        self._burp_log("\nIf the app you want isn't listed above, its traffic is NOT being redirected — select it in the target "
                        "picker and click 'Generate Capture-Traffic Script' or 'Enable Redirect' for it (this is additive, it "
                        "won't remove any rule already listed here).")
        self.update_task_state("Active capture rules listed.", "success")

    # ---------------------------------------------------------------------
    # NATIVE SSL BYPASS DECK
    # ---------------------------------------------------------------------
    def generate_native_bypass_deck_ui(self):
        lbl = ctk.CTkLabel(self.view_native_bypass, text="🔒 Native Application Bypass", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(anchor="w", padx=10, pady=(5, 2))
        ctk.CTkLabel(self.view_native_bypass,
            text="WHAT THIS TAB IS FOR: bypassing SSL pinning / root-RASP checks on NATIVE (Java/Kotlin, non-Flutter) apps. "
                 "Two independent approaches are provided below — use whichever matches your workflow, or both:\n"
                 "  • Frida-Based Bypass: live, in-process attach — fast for one-off testing, but nothing persists after the app restarts or the phone reboots.\n"
                 "  • LSPosed Module Bypass: installs a persistent Xposed/LSPosed module you built separately — survives relaunches, matches a real "
                 "engagement workflow (build a dedicated module in Android Studio, then install + scope it here).\n"
                 "HOW TO USE: ① pick the target app, ② route its traffic to Burp, ③ run ONE of the two bypass sections below.",
            font=ctk.CTkFont(size=10), text_color="#A0A0A5", anchor="w", justify="left", wraplength=820).pack(anchor="w", padx=10, pady=(0, 10))

        combo = self._build_target_selector_card(self.view_native_bypass)
        self.cbo_native_apps = combo
        self._build_frida_server_card(self.view_native_bypass, owns_deploy=False)
        self._build_traffic_routing_card(self.view_native_bypass, combo, step_num="②")

        # --- Approach A: Frida-based bypass (live attach) ---
        card_frida = ctk.CTkFrame(self.view_native_bypass, fg_color="#16161A", corner_radius=6)
        card_frida.pack(fill="x", pady=4)
        ctk.CTkLabel(card_frida, text="③A Frida-Based Bypass (live attach — requires Frida server deployed above)",
                     font=ctk.CTkFont(size=12, weight="bold"), text_color="#E91E63").pack(anchor="w", padx=15, pady=(6, 4))
        sub_fr = ctk.CTkFrame(card_frida, fg_color="transparent")
        sub_fr.pack(fill="x", padx=15, pady=(0, 10))
        ctk.CTkButton(sub_fr, text="Run SSL Pinning Bypass", width=170, fg_color="#C2185B", hover_color="#D81B60",
                      command=lambda: self.start_bypass_script("ssl", combo)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(sub_fr, text="Run Root Detection Bypass", width=190, fg_color="#C2185B", hover_color="#D81B60",
                      command=lambda: self.start_bypass_script("root", combo)).pack(side="left", padx=5)
        ctk.CTkButton(sub_fr, text="Run Both", width=100, fg_color="#AD1457", hover_color="#C2185B",
                      command=lambda: self.start_bypass_script("both", combo)).pack(side="left", padx=5)
        ctk.CTkButton(sub_fr, text="Detach", width=100, fg_color="#37474F", hover_color="#455A64",
                      command=self.stop_dynamic_session).pack(side="right")

        sub_fr_b = ctk.CTkFrame(card_frida, fg_color="transparent")
        sub_fr_b.pack(fill="x", padx=15, pady=(0, 6))
        ctk.CTkButton(sub_fr_b, text="Load Custom Script...", width=170, fg_color="#37474F", hover_color="#455A64",
                      command=self.browse_custom_frida_script).pack(side="left", padx=(0, 5))
        self.lbl_custom_script = ctk.CTkLabel(sub_fr_b, text="No custom script loaded.", text_color="#A0A0A5", anchor="w")
        self.lbl_custom_script.pack(side="left", padx=5)
        self.btn_run_custom_bypass = ctk.CTkButton(sub_fr_b, text="Run Custom Script", width=150, fg_color="#AD1457", hover_color="#C2185B",
                                                     state="disabled", command=lambda: self.start_bypass_script("custom", combo))
        self.btn_run_custom_bypass.pack(side="right")

        native_frida_results_box = ctk.CTkTextbox(card_frida, fg_color="#09090B", text_color="#00E676", font=ctk.CTkFont(family="Consolas", size=12), height=120)
        native_frida_results_box.pack(fill="x", padx=15, pady=(0, 12))
        self.frida_attach_results_boxes.append(native_frida_results_box)

        # --- Approach B: LSPosed module bypass (cmd-driven, persistent) ---
        card_lspd = ctk.CTkFrame(self.view_native_bypass, fg_color="#16161A", corner_radius=6)
        card_lspd.pack(fill="both", expand=True, pady=4)
        ctk.CTkLabel(card_lspd, text="③B LSPosed Module Bypass (cmd-driven — install + scope a pre-built module)",
                     font=ctk.CTkFont(size=12, weight="bold"), text_color="#00E676").pack(anchor="w", padx=15, pady=(6, 2))
        ctk.CTkLabel(card_lspd,
            text="Requires LSPosed already active on the device (Zygisk/KernelSU-Next, etc.) and a module APK you built separately "
                 "(e.g. in Android Studio). This installs it, enables it, and scopes it to the target app via adb + sqlite3 against "
                 "LSPosed's own modules_config.db — the same commands used manually during a real engagement. "
                 "⚠ Reboot the device after scoping — LSPosed only applies scope changes on next boot.",
            font=ctk.CTkFont(size=10), text_color="#A0A0A5", anchor="w", justify="left", wraplength=820).pack(anchor="w", padx=15, pady=(0, 6))

        sub_l1 = ctk.CTkFrame(card_lspd, fg_color="transparent")
        sub_l1.pack(fill="x", padx=15, pady=(0, 6))
        ctk.CTkButton(sub_l1, text="Select Module APK", width=150, fg_color="#37474F", hover_color="#455A64",
                      command=self.browse_lspd_module_apk).pack(side="left", padx=(0, 5))
        self.lbl_lspd_apk = ctk.CTkLabel(sub_l1, text="No module APK selected.", text_color="#A0A0A5", anchor="w")
        self.lbl_lspd_apk.pack(side="left", padx=5)
        ctk.CTkButton(sub_l1, text="Install Module APK", width=160, fg_color="#2E7D32", hover_color="#388E3C",
                      command=self.start_lspd_install).pack(side="right")

        sub_l2 = ctk.CTkFrame(card_lspd, fg_color="transparent")
        sub_l2.pack(fill="x", padx=15, pady=(0, 10))
        ctk.CTkLabel(sub_l2, text="Module Package:").pack(side="left", padx=(0, 5))
        self.ent_lspd_module_pkg = ctk.CTkEntry(sub_l2, width=260, placeholder_text="e.g. com.example.app.cug")
        self.ent_lspd_module_pkg.pack(side="left", padx=(0, 15))
        ctk.CTkButton(sub_l2, text="Enable + Scope to Target App", width=200, fg_color="#5E35B1", hover_color="#6F35B1",
                      command=lambda: self.start_lspd_scope(combo)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(sub_l2, text="Verify Scope", width=130, fg_color="#0288D1", hover_color="#039BE5",
                      command=lambda: self.start_lspd_verify(combo)).pack(side="left", padx=5)

        self.lspd_results_box = ctk.CTkTextbox(card_lspd, fg_color="#09090B", text_color="#00E676", font=ctk.CTkFont(family="Consolas", size=12), height=140)
        self.lspd_results_box.pack(fill="both", expand=True, padx=15, pady=(0, 12))

    # ---------------------------------------------------------------------
    # FLUTTER APPLICATION BYPASS DECK
    # ---------------------------------------------------------------------
    def generate_flutter_bypass_deck_ui(self):
        lbl = ctk.CTkLabel(self.view_flutter_bypass, text="🦋 Flutter Application Bypass", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(anchor="w", padx=10, pady=(5, 2))
        ctk.CTkLabel(self.view_flutter_bypass,
            text="WHAT THIS TAB IS FOR: bypassing SSL pinning on FLUTTER apps. libflutter.so bundles its own TLS stack, so the "
                 "generic Android SSL-pinning bypass does nothing here — this tab auto-detects the certificate-verify offset inside "
                 "libflutter.so and hooks it directly via Frida.\n"
                 "HOW TO USE: ① pick the target app, ② deploy Frida server (this tab owns that control — Native tab just mirrors its "
                 "status), ③ route traffic to Burp, ④ run the auto bypass.",
            font=ctk.CTkFont(size=10), text_color="#A0A0A5", anchor="w", justify="left", wraplength=820).pack(anchor="w", padx=10, pady=(0, 10))

        combo = self._build_target_selector_card(self.view_flutter_bypass)
        self.cbo_flutter_apps = combo
        self._build_frida_server_card(self.view_flutter_bypass, owns_deploy=True)
        self._build_traffic_routing_card(self.view_flutter_bypass, combo, step_num="③")

        card_d3 = ctk.CTkFrame(self.view_flutter_bypass, fg_color="#16161A", corner_radius=6)
        card_d3.pack(fill="both", expand=True, pady=4)
        lbl_d3 = ctk.CTkLabel(card_d3, text="④ Flutter SSL Pinning Bypass (Auto Offset Detection)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00ACC1")
        lbl_d3.pack(anchor="w", padx=15, pady=(6, 2))
        lbl_d3_warn = ctk.CTkLabel(card_d3, text="⚠ Flutter apps ONLY — does nothing on native/Java-only APKs (use the 🔒 Native Application Bypass tab for those).",
                                     font=ctk.CTkFont(size=10), text_color="#FF8A65", anchor="w", justify="left")
        lbl_d3_warn.pack(anchor="w", padx=15, pady=(0, 6))

        sub_d3a = ctk.CTkFrame(card_d3, fg_color="transparent")
        sub_d3a.pack(fill="x", padx=15, pady=(0, 6))
        self.btn_run_flutter_bypass = ctk.CTkButton(sub_d3a, text="Run Auto Flutter SSL Bypass", width=200, fg_color="#00838F", hover_color="#00ACC1",
                                                      command=lambda: self.start_flutter_auto_bypass(combo))
        self.btn_run_flutter_bypass.pack(side="left", padx=(0, 5))
        self.lbl_flutter_apk = ctk.CTkLabel(sub_d3a, text="No APK selected yet (will prompt, or reuse the Android tab's APK).", text_color="#A0A0A5", anchor="w")
        self.lbl_flutter_apk.pack(side="left", padx=5)

        sub_d3b = ctk.CTkFrame(card_d3, fg_color="transparent")
        sub_d3b.pack(fill="x", padx=15, pady=(0, 4))
        self.lbl_flutter_pipeline = ctk.CTkLabel(sub_d3b, text="Status: idle — not run yet.", text_color="#A0A0A5", anchor="w")
        self.lbl_flutter_pipeline.pack(side="left", padx=(0, 5))

        sub_d3c = ctk.CTkFrame(card_d3, fg_color="transparent")
        sub_d3c.pack(fill="x", padx=15, pady=(0, 10))
        self.lbl_flutter_confidence = ctk.CTkLabel(sub_d3c, text="Confidence: —", text_color="#A0A0A5", anchor="w", width=260)
        self.lbl_flutter_confidence.pack(side="left", padx=(0, 15))
        self.lbl_flutter_offset = ctk.CTkLabel(sub_d3c, text="Offset: —", text_color="#A0A0A5", anchor="w", width=160)
        self.lbl_flutter_offset.pack(side="left", padx=(0, 15))
        self.lbl_flutter_hits = ctk.CTkLabel(sub_d3c, text="Hook Hits: not attached yet", text_color="#A0A0A5", anchor="w")
        self.lbl_flutter_hits.pack(side="left")

        lbl_d3_res = ctk.CTkLabel(card_d3, text="Flutter Bypass Diagnostics (extract / scan / attach / runtime hook confirmation)", font=ctk.CTkFont(size=11, weight="bold"), text_color="#00E5FF")
        lbl_d3_res.pack(anchor="w", padx=15, pady=(0, 4))
        self.flutter_results_box = ctk.CTkTextbox(card_d3, fg_color="#09090B", text_color="#00E676", font=ctk.CTkFont(family="Consolas", size=12), height=140)
        self.flutter_results_box.pack(fill="both", expand=True, padx=15, pady=(0, 12))
        self.frida_attach_results_boxes.append(self.flutter_results_box)

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
                self._set_device_env_status("No device detected.", "#FF1744")
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
            self._set_device_env_status(f"ABI={abi} | Android {android_version} | {root_status}", text_color)
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
                self._set_frida_status("su denied - grant Magisk ADB access first.", "#FF1744")
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
                self._set_frida_status("frida-server failed to start.", "#FF1744")
                self.update_task_state("Frida deploy failed.", "failed")
                self.btn_deploy_frida.configure(state="normal")
                return

            subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"], creationflags=SUBPROCESS_FLAGS)
            self.log(f"\n[+] frida-server {version} ({arch}) deployed and running on device.")
            self._set_frida_status(f"frida-server {version} running.", "#00E676")
            self.update_task_state("Frida server deployed.", "success")
        except Exception as e:
            self.log(f"[-] Frida server deploy exception: {str(e)}")
            self.update_task_state("Frida deploy failed.", "failed")
        self.btn_deploy_frida.configure(state="normal")

    # ---------------------------------------------------------------------
    # DYNAMIC TESTING DECK — ROUTE TRAFFIC TO BURP (ADB REVERSE + IPTABLES NAT)
    # ---------------------------------------------------------------------
    def _burp_log(self, msg):
        for box in self.burp_results_boxes:
            if box.winfo_exists():
                box.insert("end", msg + "\n")
                box.see("end")

    def _burp_clear_log(self):
        for box in self.burp_results_boxes:
            if box.winfo_exists():
                box.delete("1.0", "end")

    def _run_adb_su(self, cmd_str):
        """Runs a command as root on the device via `adb shell su -c`. Returns (returncode, combined_output)."""
        proc = subprocess.run(["adb", "shell", "su", "-c", cmd_str], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        return proc.returncode, (proc.stdout + proc.stderr).strip()

    def _burp_get_port(self):
        port = (self.burp_port_var.get() or "").strip() or "8080"
        if not port.isdigit():
            messagebox.showwarning("Invalid Port", "Burp port must be numeric.")
            return None
        return port

    def _burp_check_rules(self, port):
        """
        Re-reads the live iptables NAT table from the device and checks whether our
        DNAT rules are actually present — this is the real proof, not an assumption
        from a zero exit code. Returns (has_443, has_80, raw_output).
        """
        rc, output = self._run_adb_su("iptables -t nat -L OUTPUT -n --line-numbers")
        target_re = re.escape(f"to:127.0.0.1:{port}")
        has_443 = False
        has_80 = False
        for line in output.splitlines():
            if "DNAT" not in line or not re.search(target_re, line):
                continue
            if re.search(r"dpt:443\b", line):
                has_443 = True
            if re.search(r"dpt:80\b", line):
                has_80 = True
        return has_443, has_80, output

    def _burp_find_matching_line_numbers(self, port):
        """
        Returns [(line_num, full_line_text), ...] for OUTPUT-chain DNAT rules targeting
        127.0.0.1:<port> — regardless of whether they're the broad unscoped rule (from
        'Enable Redirect') or a UID-scoped one (from the capture-traffic script / manual
        setup). Deleting by line number (rather than reconstructing the exact rule spec
        for `-D`) works no matter which mechanism added the rule, since `-D <num>` matches
        by position, not by a full field-for-field match that scoped rules would fail.
        """
        rc, output = self._run_adb_su("iptables -t nat -L OUTPUT -n --line-numbers")
        target_re = re.escape(f"to:127.0.0.1:{port}")
        matches = []
        for line in output.splitlines():
            if "DNAT" not in line or not re.search(target_re, line):
                continue
            m = re.match(r"^\s*(\d+)\s", line)
            if m:
                matches.append((int(m.group(1)), line.strip()))
        return matches

    def start_burp_redirect_enable(self):
        port = self._burp_get_port()
        if not port:
            return
        self._burp_clear_log()
        self._set_burp_status("Status: enabling redirect...", "#FFB300")
        self.update_task_state(f"[Burp] Routing device traffic to 127.0.0.1:{port} via adb reverse + iptables...", "running")
        threading.Thread(target=self.burp_redirect_enable_worker, args=(port,), daemon=True).start()

    def burp_redirect_enable_worker(self, port):
        try:
            self._burp_log(f"[*] adb reverse tcp:{port} tcp:{port}  (tunnels the device's loopback port back to Burp on this machine)")
            rev = subprocess.run(["adb", "reverse", f"tcp:{port}", f"tcp:{port}"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            rev_out = (rev.stdout + rev.stderr).strip()
            self._burp_log(rev_out if rev_out else "(no output)")
            if rev.returncode != 0:
                self._burp_log("[FAIL] adb reverse failed — is a device/emulator connected via 'adb devices'?")
                self._set_burp_status("Status: FAILED — adb reverse error", "#FF5252")
                self.update_task_state("Burp redirect failed - adb reverse error.", "failed")
                return

            self._burp_log(f"[*] iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:{port}")
            rc443, out443 = self._run_adb_su(f"iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:{port}")
            self._burp_log(out443 if out443 else f"(no output, exit code {rc443})")

            self._burp_log(f"[*] iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to-destination 127.0.0.1:{port}")
            rc80, out80 = self._run_adb_su(f"iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:{port}")
            self._burp_log(out80 if out80 else f"(no output, exit code {rc80})")

            combined = (out443 + out80).lower()
            if "permission denied" in combined or "not permitted" in combined:
                self._burp_log("[FAIL] su denied. Grant ADB shell root access (e.g. in Magisk) and retry.")
                self._set_burp_status("Status: FAILED — root access denied", "#FF5252")
                self.update_task_state("Burp redirect failed - root denied.", "failed")
                return
            if "not found" in combined or "inaccessible" in combined:
                self._burp_log("[FAIL] iptables not available on this device/emulator.")
                self._set_burp_status("Status: FAILED — iptables unavailable", "#FF5252")
                self.update_task_state("Burp redirect failed - iptables unavailable.", "failed")
                return
            if rc443 != 0 or rc80 != 0:
                self._burp_log(f"[FAIL] iptables returned a non-zero exit code (443: {rc443}, 80: {rc80}) even though no "
                                f"recognizable error text was in the output — the rule was likely NOT added. See raw output above.")
                self._set_burp_status(f"Status: FAILED — iptables exit code 443:{rc443} 80:{rc80}", "#FF5252")
                self.update_task_state("Burp redirect failed - iptables non-zero exit.", "failed")
                return

            self._burp_log("[*] Re-reading the live iptables NAT table to confirm the rules actually took effect...")
            self._burp_finish_verify(port, action_label="Redirect enabled")
        except Exception as e:
            self._burp_log(f"[FAIL] Exception: {str(e)}")
            self._set_burp_status("Status: FAILED — exception", "#FF5252")
            self.update_task_state("Burp redirect failed.", "failed")

    def start_burp_redirect_verify(self):
        port = self._burp_get_port()
        if not port:
            return
        self._burp_clear_log()
        self.update_task_state(f"[Burp] Verifying iptables NAT rules for port {port}...", "running")
        threading.Thread(target=self.burp_redirect_verify_worker, args=(port,), daemon=True).start()

    def burp_redirect_verify_worker(self, port):
        try:
            self._burp_finish_verify(port, action_label="Verification")
        except Exception as e:
            self._burp_log(f"[FAIL] Exception: {str(e)}")
            self.update_task_state("Burp redirect verification failed.", "failed")

    def _burp_finish_verify(self, port, action_label):
        """Shared close-the-loop check: re-reads iptables state and reports what's ACTUALLY there."""
        has_443, has_80, raw = self._burp_check_rules(port)
        self._burp_log("---- iptables -t nat -L OUTPUT -n --line-numbers ----")
        self._burp_log(raw if raw else "(empty output — su may have failed silently)")
        self._burp_log("-----------------------------------------------------")

        if has_443 and has_80:
            self._burp_log(f"[OK] Confirmed: both port 443 and 80 are DNAT'd to 127.0.0.1:{port}.")
            self._set_burp_status(f"Status: ROUTED — CONFIRMED (443 & 80 -> 127.0.0.1:{port})", "#00E676")
            self.update_task_state(f"{action_label}: traffic redirect confirmed on-device.", "success")
        elif has_443 or has_80:
            missing = "80" if has_443 else "443"
            self._burp_log(f"[WARN] Only one of the two rules is present — port {missing} is NOT redirected.")
            self._set_burp_status(f"Status: PARTIAL — port {missing} not redirected", "#FFB300")
            self.update_task_state(f"{action_label}: partial redirect only.", "failed")
        else:
            self._burp_log("[FAIL] No matching DNAT rule found for this port. Traffic is NOT being routed to Burp.")
            self._set_burp_status("Status: NOT ROUTED — no matching rules found", "#FF5252")
            self.update_task_state(f"{action_label}: no redirect rules found.", "failed")

        self._burp_log("\nReminder: in Burp, Proxy -> Settings -> add a listener on 127.0.0.1:" + port + " with 'Support invisible proxying' enabled, then generate traffic in the app and check Proxy -> HTTP history.")

    def start_burp_redirect_revert(self):
        port = self._burp_get_port()
        if not port:
            return
        self._burp_clear_log()
        self.update_task_state(f"[Burp] Reverting traffic redirect for port {port}...", "running")
        threading.Thread(target=self.burp_redirect_revert_worker, args=(port,), daemon=True).start()

    def burp_redirect_revert_worker(self, port):
        try:
            self._burp_log(f"[*] Scanning iptables nat OUTPUT chain for any DNAT rule targeting 127.0.0.1:{port} "
                            f"(broad or UID-scoped — either kind gets removed)...")
            matches = self._burp_find_matching_line_numbers(port)
            if not matches:
                self._burp_log("[*] No matching rules found in the table — nothing to delete.")
            for line_num, line_text in sorted(matches, key=lambda t: t[0], reverse=True):
                self._burp_log(f"[*] iptables -t nat -D OUTPUT {line_num}   (removing: {line_text})")
                _, out = self._run_adb_su(f"iptables -t nat -D OUTPUT {line_num}")
                self._burp_log(out if out else "(rule removed, no output)")

            self._burp_log(f"[*] adb reverse --remove tcp:{port}")
            rem = subprocess.run(["adb", "reverse", "--remove", f"tcp:{port}"], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            rem_out = (rem.stdout + rem.stderr).strip()
            if "not found" in rem_out.lower():
                self._burp_log("(no active reverse tunnel for this port — already removed or never enabled, that's fine)")
            else:
                self._burp_log(rem_out or "(removed)")

            has_443, has_80, raw = self._burp_check_rules(port)
            self._burp_log("---- iptables -t nat -L OUTPUT -n --line-numbers (post-revert) ----")
            self._burp_log(raw if raw else "(empty)")
            if not has_443 and not has_80:
                self._set_burp_status("Status: reverted — not routed.", "#A0A0A5")
                self.update_task_state("Burp redirect reverted.", "idle")
            else:
                self._burp_log("[WARN] A DNAT rule is still present after revert. If this persists, run 'adb reboot' to force-clear iptables state.")
                self._set_burp_status("Status: revert incomplete — rule still present", "#FFB300")
                self.update_task_state("Burp redirect revert incomplete.", "failed")
        except Exception as e:
            self._burp_log(f"[FAIL] Exception: {str(e)}")
            self.update_task_state("Burp redirect revert failed.", "failed")

    def start_burp_redirect_revert_scoped(self, combo):
        package = self._resolve_selected_target(combo, warn=True)
        if not package:
            return
        port = self._burp_get_port()
        if not port:
            return
        self._burp_clear_log()
        self.update_task_state(f"[Burp] Reverting redirect for {package} only (other apps stay active)...", "running")
        threading.Thread(target=self._burp_redirect_revert_scoped_worker, args=(package, port), daemon=True).start()

    def _burp_redirect_revert_scoped_worker(self, package, port):
        """
        Unlike burp_redirect_revert_worker (which clears EVERY rule on the port, and also
        tears down the shared adb reverse tunnel), this only deletes the rule(s) scoped to
        THIS app's UID — other apps' rules, and the adb reverse tunnel they all share, are
        left untouched. Deliberately does NOT run 'adb reverse --remove' for that reason.
        """
        try:
            uid = self._get_package_uid(package, self._burp_log)
            if not uid:
                self.update_task_state("Scoped revert failed - UID lookup failed.", "failed")
                return

            self._burp_log(f"[*] Scanning for DNAT rules scoped to {package} (UID {uid}) on port {port}...")
            matches = self._burp_find_matching_line_numbers(port)
            uid_re = re.compile(rf"owner UID match {re.escape(uid)}\b")
            uid_matches = [(n, t) for n, t in matches if uid_re.search(t)]

            if not uid_matches:
                self._burp_log(f"[*] No rule scoped to UID {uid} found — nothing to delete for this app. "
                                f"(If you meant the broad, unscoped redirect, use 'Revert (ALL Apps On This Port)' instead.)")
                self.update_task_state(f"No scoped rule found for {package}.", "idle")
                return

            for line_num, line_text in sorted(uid_matches, key=lambda t: t[0], reverse=True):
                self._burp_log(f"[*] iptables -t nat -D OUTPUT {line_num}   (removing: {line_text})")
                _, out = self._run_adb_su(f"iptables -t nat -D OUTPUT {line_num}")
                self._burp_log(out if out else "(rule removed, no output)")

            self._burp_log(f"\n[*] Re-checking — rules for OTHER apps on this port are expected to still be present below:")
            _, raw = self._run_adb_su("iptables -t nat -L OUTPUT -n --line-numbers")
            self._burp_log(raw if raw else "(empty)")
            self._burp_log(f"\n[OK] {package}'s capture rule removed. adb reverse tcp:{port} left untouched — other apps still route through it.")
            self.update_task_state(f"{package} capture reverted (other apps unaffected).", "success")
        except Exception as e:
            self._burp_log(f"[FAIL] Exception: {str(e)}")
            self.update_task_state("Scoped revert failed.", "failed")

    # ---------------------------------------------------------------------
    # SHARED — TARGET APP SCAN + BYPASS SCRIPT RUNNER
    #
    # Installed-app list is the same regardless of which tab asked for it (same phone),
    # so one scan refreshes EVERY registered combo box (self.target_app_combo_widgets).
    # Each combo's own SELECTION stays independent — scanning again only auto-picks an
    # entry for a combo that doesn't already have a real one, so it never clobbers a
    # deliberate choice already made in the other tab.
    # ---------------------------------------------------------------------
    def start_dynamic_app_scan(self):
        self.update_task_state("[ADB] Querying installed packages...", "running")
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

            for combo in self.target_app_combo_widgets:
                if not combo.winfo_exists():
                    continue
                combo.configure(values=dropdown_entries)
                current = combo.get()
                if not current or "Scan" in current or current not in self.discovered_dynamic_apps:
                    combo.set(dropdown_entries[0])
            self.update_task_state("Installed app list synced.", "success")
        except Exception:
            self.update_task_state("ADB Parser unexpected crash.", "failed")

    def start_bypass_script(self, mode, combo):
        if frida is None:
            messagebox.showerror("Frida Missing", "The 'frida' Python package is not installed.")
            return
        if mode == "custom" and not self.custom_frida_script_path:
            messagebox.showwarning("No Custom Script", "Load a custom Frida script first.")
            return
        if not self._resolve_selected_target(combo, warn=True):
            return
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
            self._dyn_log(f"[+] Loaded: {loaded_labels} against {self.dynamic_target_package}")
            self.update_task_state("Bypass script(s) loaded and running.", "success")
        except Exception as e:
            self.log(f"[-] Frida bypass exception: {str(e)}")
            self.update_task_state("Frida bypass failed.", "failed")

    def _on_frida_message(self, message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict) and payload.get("tag") == "flutter_ssl_bypass":
                self._on_flutter_bypass_message(payload)
                return
            text = payload
        elif message["type"] == "error":
            text = f"ERROR: {message.get('stack', message.get('description', message))}"
        else:
            text = str(message)
        self.log(f"[Frida] {text}")
        self._dyn_log(text)

    # ---------------------------------------------------------------------
    # FLUTTER SSL BYPASS DECK — runtime callbacks for the "Run Auto Flutter SSL Bypass"
    # button on the 🎯 Flutter SSL Bypass tab (UI itself lives in generate_flutter_bypass_deck_ui).
    # Kept physically here (not moved) since it shares bypass_script_worker/_on_frida_message/
    # stop_dynamic_session with the native flow just below — flutter_auto_bypass_worker calls
    # straight into bypass_script_worker("custom") to actually attach.
    # ---------------------------------------------------------------------
    def _flutter_log(self, msg):
        self.flutter_results_box.insert("end", msg + "\n")
        self.flutter_results_box.see("end")

    def _on_flutter_bypass_message(self, payload):
        event = payload.get("event")
        if event == "module_found":
            self._flutter_log(f"[INFO] libflutter.so loaded @ {payload.get('base')} — attaching hook at {payload.get('target')} (offset {payload.get('offset')})")
            self.lbl_flutter_pipeline.configure(text="Status: module found, installing hook...", text_color="#FFB300")
        elif event == "hook_installed":
            self._flutter_log("[OK] Hook installed. Waiting for the app to make an HTTPS/TLS request to confirm it actually fires...")
            self.lbl_flutter_pipeline.configure(text="Status: hook installed — waiting for traffic to confirm", text_color="#00E5FF")
            self.flutter_hit_count = 0
            self.lbl_flutter_hits.configure(text="Hook Hits: 0 (waiting for traffic)", text_color="#FFB300")
            self._start_flutter_watchdog()
        elif event == "hook_attach_failed":
            self._flutter_log(f"[FAIL] Interceptor.attach threw: {payload.get('error')} — the detected offset does not point at valid code. Do not trust this bypass.")
            self.lbl_flutter_pipeline.configure(text="Status: hook attach FAILED — offset is wrong", text_color="#FF5252")
            self.lbl_flutter_hits.configure(text="Hook Hits: attach failed", text_color="#FF5252")
        elif event == "module_not_found":
            self._flutter_log("[FAIL] libflutter.so is not loaded in the running process. Wrong target selected, app isn't Flutter, or it hasn't finished starting yet.")
            self.lbl_flutter_pipeline.configure(text="Status: libflutter.so NOT FOUND in process", text_color="#FF5252")
        elif event == "hit":
            self.flutter_hit_count = payload.get("count", self.flutter_hit_count + 1)
            self._flutter_log(f"[OK] Hook fired (#{self.flutter_hit_count}) — original retval={payload.get('before_retval')}, forced retval={payload.get('forced_retval')}")
            self.lbl_flutter_hits.configure(text=f"Hook Hits: {self.flutter_hit_count} — CONFIRMED WORKING", text_color="#00E676")
            self.lbl_flutter_pipeline.configure(text="Status: bypass CONFIRMED — cert validation is being forced to pass", text_color="#00E676")

    def _start_flutter_watchdog(self):
        if self.flutter_watchdog_timer:
            self.flutter_watchdog_timer.cancel()
        self.flutter_watchdog_timer = threading.Timer(15.0, self._flutter_watchdog_fire)
        self.flutter_watchdog_timer.daemon = True
        self.flutter_watchdog_timer.start()

    def _flutter_watchdog_fire(self):
        if self.flutter_hit_count == 0:
            self._flutter_log("[WARN] No hook activity 15s after attach. Either the app hasn't made an HTTPS request yet (open a screen that hits the network), or the detected offset is wrong for this build.")
            self.lbl_flutter_pipeline.configure(text="Status: no hook activity yet — trigger network traffic in the app", text_color="#FFB300")

    def browse_custom_frida_script(self):
        filepath = filedialog.askopenfilename(title="Select Custom Frida Script", filetypes=[("Frida JS", "*.js")])
        if filepath:
            self.custom_frida_script_path = filepath
            self.lbl_custom_script.configure(text=os.path.basename(filepath), text_color="#00E676")
            self.btn_run_custom_bypass.configure(state="normal")

    def start_flutter_auto_bypass(self, combo):
        if frida is None:
            messagebox.showerror("Frida Missing", "The 'frida' Python package is not installed.")
            return
        if not self._resolve_selected_target(combo, warn=True):
            return

        apk_path = self.flutter_bypass_apk_path or self.target_apk
        if not apk_path or not os.path.isfile(apk_path):
            apk_path = filedialog.askopenfilename(
                title="Select the target app's APK (to extract libflutter.so from)",
                filetypes=[("APK Files", "*.apk")])
            if not apk_path:
                return
        self.flutter_bypass_apk_path = apk_path
        self.lbl_flutter_apk.configure(text=os.path.basename(apk_path), text_color="#FFFFFF")

        if self.flutter_watchdog_timer:
            self.flutter_watchdog_timer.cancel()
        self.flutter_hit_count = 0
        self.flutter_results_box.delete("1.0", "end")
        self.lbl_flutter_confidence.configure(text="Confidence: —", text_color="#A0A0A5")
        self.lbl_flutter_offset.configure(text="Offset: —", text_color="#A0A0A5")
        self.lbl_flutter_hits.configure(text="Hook Hits: not attached yet", text_color="#A0A0A5")
        self.lbl_flutter_pipeline.configure(text="Status: extracting libflutter.so from APK...", text_color="#FFB300")

        self.update_task_state(f"[Flutter] Analyzing {os.path.basename(apk_path)} for the SSL verify offset...", "running")
        threading.Thread(target=self.flutter_auto_bypass_worker, args=(apk_path,), daemon=True).start()

    def flutter_auto_bypass_worker(self, apk_path):
        try:
            out_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)), "flutter_bypass_generated")

            def _log(msg):
                self._flutter_log(msg)

            script_path, result = flutter_ssl_bypass.build_flutter_bypass_script(
                apk_path, self.dynamic_target_package, out_dir, log=_log)

            if not script_path:
                self._flutter_log(f"[FAIL] {result.detail}")
                self.lbl_flutter_confidence.configure(text="Confidence: NOT FOUND", text_color="#FF5252")
                self.lbl_flutter_pipeline.configure(text="Status: offset detection failed — see diagnostics below", text_color="#FF5252")
                self.update_task_state("Flutter SSL bypass: offset detection failed.", "failed")
                return

            if result.status == "confident":
                self.lbl_flutter_confidence.configure(text="Confidence: HIGH (all refs agree)", text_color="#00E676")
            else:
                self.lbl_flutter_confidence.configure(text=f"Confidence: AMBIGUOUS ({len(result.candidates)} candidates)", text_color="#FFB300")
                self._flutter_log(f"[WARN] {result.detail}")

            self.lbl_flutter_offset.configure(text=f"Offset: {hex(result.offset)}", text_color="#00E5FF")
            self._flutter_log(f"[OK] Script generated: {script_path}")

            self.custom_frida_script_path = script_path
            self.lbl_custom_script.configure(text=os.path.basename(script_path), text_color="#00E676")
            self.btn_run_custom_bypass.configure(state="normal")
            self.lbl_flutter_pipeline.configure(text="Status: attaching Frida session...", text_color="#FFB300")
            self.update_task_state(f"Flutter offset {hex(result.offset)} detected ({result.status}). Attaching...", "running")

            self.bypass_script_worker("custom")
        except Exception as e:
            self._flutter_log(f"[FAIL] Unexpected exception: {str(e)}")
            self.lbl_flutter_pipeline.configure(text="Status: unexpected failure — see diagnostics below", text_color="#FF5252")
            self.update_task_state("Flutter SSL bypass failed.", "failed")

    def stop_dynamic_session(self):
        try:
            if self.flutter_watchdog_timer:
                self.flutter_watchdog_timer.cancel()
                self.flutter_watchdog_timer = None
            if self.frida_script:
                self.frida_script.unload()
                self.frida_script = None
            if self.frida_session:
                self.frida_session.detach()
                self.frida_session = None
            self.log("\n[*] Detached from Frida session.")
            self.update_task_state("Dynamic session detached.", "idle")
            self.lbl_flutter_pipeline.configure(text="Status: detached.", text_color="#A0A0A5")
            self.lbl_flutter_hits.configure(text="Hook Hits: session detached", text_color="#A0A0A5")
        except Exception as e:
            self.log(f"[-] Detach exception: {str(e)}")

    # ---------------------------------------------------------------------
    # NATIVE APPLICATION BYPASS DECK — LSPOSED MODULE BYPASS (cmd-driven, persistent)
    #
    # This is deliberately NOT Frida. It installs a pre-built LSPosed/Xposed module APK
    # and scopes it to the target app by writing directly into LSPosed's own SQLite config
    # (/data/adb/lspd/config/modules_config.db) via `adb shell su -c sqlite3` — the same
    # mechanism the LSPosed Manager app itself uses, and the same one used manually
    # during a real engagement. The module keeps working across app
    # relaunches with no live attach required (unlike the Frida section above), but scope
    # changes only take effect after a reboot.
    # ---------------------------------------------------------------------
    LSPD_MODULES_DB = "/data/adb/lspd/config/modules_config.db"
    _PKG_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")

    def _lspd_log(self, msg):
        if self.lspd_results_box.winfo_exists():
            self.lspd_results_box.insert("end", msg + "\n")
            self.lspd_results_box.see("end")
        self.log(msg)

    def _lspd_get_module_pkg(self):
        pkg = (self.ent_lspd_module_pkg.get() or "").strip()
        if not pkg or not self._PKG_NAME_RE.match(pkg):
            messagebox.showwarning("Invalid Module Package", "Enter the LSPosed module's own package name (e.g. com.example.mymodule).")
            return None
        return pkg

    def browse_lspd_module_apk(self):
        filepath = filedialog.askopenfilename(title="Select LSPosed Module APK", filetypes=[("APK Files", "*.apk")])
        if filepath:
            self.lspd_module_apk_path = filepath
            self.lbl_lspd_apk.configure(text=os.path.basename(filepath), text_color="#FFFFFF")

    def start_lspd_install(self):
        if not self.lspd_module_apk_path:
            messagebox.showwarning("No Module APK", "Select the LSPosed module's APK first.")
            return
        self.update_task_state(f"[LSPosed] Installing {os.path.basename(self.lspd_module_apk_path)}...", "running")
        threading.Thread(target=self.lspd_install_worker, daemon=True).start()

    def lspd_install_worker(self):
        self._lspd_log(f"[*] adb install -r {self.lspd_module_apk_path}")
        proc = subprocess.run(["adb", "install", "-r", self.lspd_module_apk_path], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        out = (proc.stdout + proc.stderr).strip()
        self._lspd_log(out if out else "(no output)")
        if "Success" in out:
            self._lspd_log("[OK] Installed. Now open the LSPosed Manager app on the device once so it registers the new module, "
                            "then enter its package name below and click 'Enable + Scope to Target App'.")
            self.update_task_state("LSPosed module installed.", "success")
        else:
            self._lspd_log("[FAIL] Install did not report Success — check the output above.")
            self.update_task_state("LSPosed module install failed.", "failed")

    def start_lspd_scope(self, combo):
        module_pkg = self._lspd_get_module_pkg()
        if not module_pkg:
            return
        target_pkg = self._resolve_selected_target(combo, warn=True)
        if not target_pkg:
            return
        self.update_task_state(f"[LSPosed] Scoping {module_pkg} to {target_pkg}...", "running")
        threading.Thread(target=self.lspd_scope_worker, args=(module_pkg, target_pkg), daemon=True).start()

    def lspd_scope_worker(self, module_pkg, target_pkg):
        self._lspd_log(f"[*] Enabling module '{module_pkg}' in LSPosed's config db...")
        sql_enable = f"UPDATE modules SET enabled=1 WHERE module_pkg_name='{module_pkg}';"
        rc, out = self._run_adb_su(f'sqlite3 {self.LSPD_MODULES_DB} "{sql_enable}"')
        if out:
            self._lspd_log(out)

        self._lspd_log(f"[*] Scoping '{module_pkg}' to target app '{target_pkg}'...")
        sql_scope = (f"INSERT OR IGNORE INTO scope (mid, app_pkg_name, user_id) "
                     f"SELECT mid, '{target_pkg}', 0 FROM modules WHERE module_pkg_name='{module_pkg}';")
        rc2, out2 = self._run_adb_su(f'sqlite3 {self.LSPD_MODULES_DB} "{sql_scope}"')
        if out2:
            self._lspd_log(out2)

        combined = (out + out2).lower()
        if "no such table" in combined or "unable to open" in combined or "not found" in combined:
            self._lspd_log("[FAIL] Could not reach LSPosed's config db. Is LSPosed actually installed and active on this device (check "
                            "the LSPosed Manager app), and is su access granted?")
            self.update_task_state("LSPosed scoping failed.", "failed")
            return

        self._lspd_log("[*] Verifying the module is registered and the scope row was written...")
        self._lspd_verify_impl(module_pkg, target_pkg)
        self._lspd_log("\n[!] REBOOT REQUIRED — LSPosed only applies scope changes on next boot ('adb reboot'). "
                        "After reboot, relaunch the target app and confirm the module's own hook logs fire.")
        self.update_task_state(f"LSPosed scope written for {target_pkg} — reboot required.", "success")

    def start_lspd_verify(self, combo):
        module_pkg = self._lspd_get_module_pkg()
        if not module_pkg:
            return
        target_pkg = self._resolve_selected_target(combo, warn=True)
        if not target_pkg:
            return
        self.update_task_state(f"[LSPosed] Verifying scope for {module_pkg}...", "running")
        threading.Thread(target=self._lspd_verify_impl, args=(module_pkg, target_pkg), daemon=True).start()

    def _lspd_verify_impl(self, module_pkg, target_pkg):
        sql_mod = f"SELECT mid, module_pkg_name, enabled FROM modules WHERE module_pkg_name='{module_pkg}';"
        _, mod_out = self._run_adb_su(f'sqlite3 {self.LSPD_MODULES_DB} "{sql_mod}"')
        self._lspd_log(f"---- modules row for '{module_pkg}' ----")
        self._lspd_log(mod_out if mod_out else "(EMPTY — module not registered yet. Open the LSPosed Manager app on the device once, then retry.)")

        sql_scope = f"SELECT * FROM scope WHERE app_pkg_name='{target_pkg}';"
        _, scope_out = self._run_adb_su(f'sqlite3 {self.LSPD_MODULES_DB} "{sql_scope}"')
        self._lspd_log(f"---- scope rows for '{target_pkg}' ----")
        self._lspd_log(scope_out if scope_out else "(EMPTY — not scoped yet.)")

        if mod_out and scope_out:
            self._lspd_log("[OK] Module is registered AND scoped to the target app. Reboot (if you haven't since scoping) and test.")
            self.update_task_state("LSPosed scope verified.", "success")
        else:
            self.update_task_state("LSPosed scope verification: incomplete.", "failed")


if __name__ == "__main__":
    try:
        print("[*] Spawning CustomTkinter Engine Window...")
        main_window = NKCyberSuiteMobile()
        main_window.mainloop()
        print("[+] Window closed cleanly.")
    except Exception as error:
        print(f"\n[-] ENGINE RUNTIME CRASH LOG:\n{error}\n")
