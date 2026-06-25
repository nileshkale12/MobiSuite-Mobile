import os
import subprocess
import threading
import zipfile
import shutil
import sys
import urllib.request
import importlib.util
import time

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

ctk.set_appearance_mode("Dark")     
ctk.set_default_color_theme("blue") 


class NKCyberSuiteMobile(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("MobiSuite v1.0.0")
        self.geometry("1100x860")
        self.minsize(1000, 780)
        
        # SAFE CROSS-PLATFORM WINDOW GEOMETRY DECORATION UNLOCK[cite: 1]
        self.resizable(True, True)
        if IS_LINUX:
            self.attributes('-type', 'normal')
        self.update_idletasks()
        
        # Operational Context State Trackers
        self.target_apk = ""
        self.rebuild_dir = ""
        self.unsigned_apk_path = "" 
        self.selected_merge_dir = ""
        self.discovered_android_apps = {}  
        self.discovered_ios_apps = {}
        self.ios_dest_dir = ""

        ext = ".exe" if sys.platform == "win32" else ""
        self.bin_names = [f"adb{ext}", "apktool.jar", "APKEditor.jar", f"zipalign{ext}", "apksigner.jar"]
        self.bin_status_labels = {}
        self.pip_packages = ["customtkinter", "paramiko", "scp", "pyinstaller", "cryptography"]
        self.pip_status_labels = {}

        # ---------------------------------------------------------------------
        # LEFT NAVIGATION SIDEBAR RAIL
        # ---------------------------------------------------------------------
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1A1A1E")
        self.sidebar.pack(side="left", fill="y")
        
        # Restored Diamond Logo Brand Header Configuration
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
        
        # Author Verification & Production License Footer[cite: 2]
        copyright_lbl = ctk.CTkLabel(self.sidebar, text="© 2026 Nilesh Kale\nAll Rights Reserved\nVersion 1.0.0", font=ctk.CTkFont(size=10), text_color="gray", justify="center")
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
        # MAIN DECK DISPLAY CONTAINER
        # ---------------------------------------------------------------------
        self.main_deck = ctk.CTkFrame(self, corner_radius=0, fg_color="#0F0F12")
        self.main_deck.pack(side="right", fill="both", expand=True)
        
        self.view_android = ctk.CTkFrame(self.main_deck, fg_color="transparent")
        self.view_ios = ctk.CTkFrame(self.main_deck, fg_color="transparent")
        self.view_settings = ctk.CTkFrame(self.main_deck, fg_color="transparent")
        self.view_console = ctk.CTkFrame(self.main_deck, fg_color="transparent")
        
        self.generate_android_deck_ui()
        self.generate_ios_deck_ui()
        self.generate_settings_deck_ui()
        self.generate_console_deck_ui()
        
        self.switch_deck_context("android")
        
        # Launch tracking loop pools
        threading.Thread(target=self.verify_and_download_dependencies, daemon=True).start()
        threading.Thread(target=self.device_connection_hud_ticker, daemon=True).start()

    def log(self, message):
        self.console_box.insert("end", message + "\n")
        self.console_box.see("end")

    # -------------------------------------------------------------------------
    # LIVE HUDS SYNC CONTROL PIPELINE
    # -------------------------------------------------------------------------
    def update_task_state(self, task_description, state_type):
        """Asynchronously triggers thread-safe UI status banner adaptations."""
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
        
        self.view_android.pack_forget()
        self.view_ios.pack_forget()
        self.view_settings.pack_forget()
        self.view_console.pack_forget()

        if target_deck == "android":
            self.btn_nav_android.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_android.pack(fill="both", expand=True, padx=15, pady=15)
        elif target_deck == "ios":
            self.btn_nav_ios.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_ios.pack(fill="both", expand=True, padx=15, pady=15)
        elif target_deck == "settings":
            self.btn_nav_settings.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_settings.pack(fill="both", expand=True, padx=15, pady=15)
            self.check_local_tools_inventory()
        elif target_deck == "console":
            self.btn_nav_console.configure(fg_color="#2A2B36", text_color="#FFFFFF")
            self.view_console.pack(fill="both", expand=True, padx=15, pady=15)

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

    # -------------------------------------------------------------------------
    # ENVIRONMENT CONTROL CENTER
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # ANDROID DECK LAYOUTS
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # iOS OPERATIONAL UTILITIES
    # -------------------------------------------------------------------------
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

    def refresh_interface_locks(self):
        self.btn_decompile.configure(state="normal" if self.target_apk else "disabled")
        self.btn_rebuild.configure(state="normal" if self.rebuild_dir else "disabled")
        self.btn_sign_only.configure(state="normal" if self.unsigned_apk_path else "disabled")

    # -------------------------------------------------------------------------
    # OPERATIONAL CORE BUSINESS WORKER EXECUTION NODES
    # -------------------------------------------------------------------------
    def verify_and_download_dependencies(self):
        for pkg in self.pip_packages:
            if importlib.util.find_spec(pkg) is None:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg] + KALI_FLAG, creationflags=SUBPROCESS_FLAGS)
                except Exception as ex:
                    self.log(f"[-] Pip module extraction fault: {str(ex)}")

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
                self.log(f"[*] Core component asset missing. Fetching secure block: {name}...")
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req) as response, open(target_path, 'wb') as out_file:
                        shutil.copyfileobj(response, out_file)
                    self.log(f"[+] Package synced: {name}")
                except Exception as ex:
                    self.log(f"[-] Dependency download failure: {name} -> {ex}")
                    
        self.log("[+] Environmental scanning tasks complete. Engine online and verified.")
        self.update_task_state("System Standby Ready", "idle")
        self.check_local_tools_inventory()

    def start_android_package_fetch(self):
        self.update_task_state("[ADB] Querying device database packages handles...", "running")
        self.log("\n[*] Querying third-party apps over ADB database handles...")
        threading.Thread(target=self.adb_fetch_packages_worker, daemon=True).start()

    def adb_fetch_packages_worker(self):
        try:
            cmd = ["adb", "shell", "pm", "list", "packages", "-3"]
            process = subprocess.run(cmd, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            
            if process.returncode != 0:
                self.log("[-] ADB Interface Failure: Confirm USB debugging connection.")
                self.update_task_state("ADB Interface Link dropped.", "failed")
                return

            self.discovered_android_apps.clear()
            dropdown_entries = []
            raw_packages = [line.replace("package:", "").strip() for line in process.stdout.splitlines() if line.startswith("package:")]

            if not raw_packages:
                self.log("[-] Active session open but device returned zero user packages entries.")
                self.update_task_state("No third-party packages found.", "failed")
                return

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
            self.log(f"[+] Synced {len(dropdown_entries)} applications successfully.")
            self.update_task_state("Applications layout synced.", "success")
        except Exception as e:
            self.log(f"[-] ADB Process Exception: {str(e)}")
            self.update_task_state("ADB Parser unexpected crash.", "failed")

    def start_android_apk_pull(self):
        selected_display = self.cbo_android_apps.get()
        if not selected_display or "Scan" in selected_display:
            messagebox.showwarning("Warning", "Run application device discovery first.")
            return
        
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
            self.log(f"\n[*] Instantiating custom application workspace targets:\n -> {app_dir}")
            
            path_proc = subprocess.run(["adb", "shell", "pm", "path", package_id], capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
            remote_paths = [line.replace("package:", "").strip() for line in path_proc.stdout.splitlines() if line.startswith("package:")]

            if not remote_paths:
                self.log("[-] Path mapping vector parsing failed via PM shell subsystem.")
                self.update_task_state("Package paths parsing failed.", "failed")
                return

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
                    if local_filename in (f"{package_id}.apk", "base.apk"):
                        base_local_path = final_local_path

            self.log(f"[+] Pull Extraction Complete: Check target folder workspace.")
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
            
            self.log(f"\n[*] Calling APKEditor merge module dependencies against: {self.selected_merge_dir}")
            merge_cmd = ["java", "-jar", "tools/APKEditor.jar", "m", "-i", self.selected_merge_dir, "-o", final_output_path]
            
            merge_proc = subprocess.Popen(merge_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=SUBPROCESS_FLAGS)
            merge_proc.wait()

            if os.path.exists(final_output_path):
                self.target_apk = final_output_path
                self.lbl_apk.configure(text=os.path.basename(self.target_apk), text_color="#00E676")
                self.btn_decompile.configure(state="normal")
                self.log(f"[+] Assembly Forged standalone package ready.")
                self.update_task_state("App bundles unified successfully.", "success")
                messagebox.showinfo("Merge Complete", f"Compiled cleanly into standalone structure!\n{final_output_path}")
            else:
                self.update_task_state("Unified archive generation parameters dropped.", "failed")
        except Exception as e:
            self.log(f"[-] Merger runtime pipeline error: {str(e)}")
            self.update_task_state("APKEditor sub-process engine error.", "failed")

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
                messagebox.showerror("Validation Error", "Invalid Target Directory!\n\nThe selected folder is missing the 'apktool.yml' signature parameter configuration file required for reassembly workflows.")
                self.rebuild_dir = ""
                self.lbl_dir.configure(text="No modified directory path selected.", text_color="#A0A0A5")
                self.btn_rebuild.configure(state="disabled")
                self.update_task_state("Invalid decompiled project folder structure.", "failed")
            else:
                self.rebuild_dir = norm_path
                self.lbl_dir.configure(text=os.path.basename(self.rebuild_dir), text_color="#00E676")
                self.btn_rebuild.configure(state="normal")
                self.update_task_state("Modded directory structural validation passed.", "idle")

    def browse_unsigned_apk(self):
        filepath = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        if filepath:
            self.unsigned_apk_path = filepath
            self.lbl_sign_apk.configure(text=os.path.basename(self.unsigned_apk_path), text_color="#FFFFFF")
            self.btn_sign_only.configure(state="normal")

    def start_decompile(self):
        self.btn_decompile.configure(state="disabled")
        self.update_task_state("[Apktool] Decompiling package assets directory structure...", "running")
        self.log("\n[*] Handing operation context off to Apktool execution nodes...")
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
            if process.returncode == 0:
                self.log(f"\n--- {terminal_success_msg} ---")
                self.update_task_state("Operation complete.", "success")
            else:
                self.log("\n--- ENGINE ERROR EXECUTION TERMINATED ---")
                self.update_task_state("Task process execution rejected.", "failed")
        except Exception as ex: 
            self.log(f"[-] Unexpected failure mapping tasks: {str(ex)}")
            self.update_task_state("Infrastructure subprocess system crash.", "failed")
        self.refresh_interface_locks()

    def standalone_sign_pipeline_worker(self):
        base_name = os.path.splitext(self.unsigned_apk_path)[0]
        aligned_apk = f"{base_name}_aligned.apk"
        final_signed_apk = f"{base_name}_SIGNED.apk"

        zipalign_bin = "tools/zipalign" if IS_LINUX else "tools/zipalign.exe"
        subprocess.run([zipalign_bin, "-p", "-f", "4", self.unsigned_apk_path, aligned_apk], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=SUBPROCESS_FLAGS)

        if not os.path.exists(aligned_apk):
            self.log("[-] Error: Optimization alignment process tracking crash.")
            self.update_task_state("Zipalign boundary optimization rejected.", "failed")
            self.refresh_interface_locks(); return

        cmd_sign = ["java", "-jar", "tools/apksigner.jar", "sign", "--ks", "tools/debug.keystore", "--ks-pass", "pass:android", "--out", final_signed_apk, aligned_apk]
        proc = subprocess.run(cmd_sign, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        
        if proc.returncode == 0:
            self.log(f"\n--- SUCCESS! Standalone Build Certified: {final_signed_apk} ---")
            self.update_task_state("Manual package signed successfully.", "success")
            if os.path.exists(aligned_apk): os.remove(aligned_apk)
        else:
            self.log("[-] Error: Keyring validation structures signature failed.")
            self.update_task_state("Apksigner cryptographic signature rejected.", "failed")
        self.refresh_interface_locks()

    def rebuild_pipeline_worker(self):
        base_name = os.path.basename(os.path.normpath(self.rebuild_dir))
        output_dir_path = os.path.dirname(os.path.normpath(self.rebuild_dir))
        unsigned_apk = os.path.join(output_dir_path, f"{base_name}_unsigned.apk")
        aligned_apk = os.path.join(output_dir_path, f"{base_name}_MODDED.apk")
        
        subprocess.run(["java", "-jar", "tools/apktool.jar", "b", self.rebuild_dir, "-o", unsigned_apk], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=SUBPROCESS_FLAGS)
        
        if not os.path.exists(unsigned_apk):
            self.log("[-] Error: Rebuild failed. Review Smali constraints.")
            self.update_task_state("Apktool reassembly compilation error.", "failed")
            self.refresh_interface_locks(); return

        zipalign_bin = "tools/zipalign" if IS_LINUX else "tools/zipalign.exe"
        subprocess.run([zipalign_bin, "-p", "-f", "4", unsigned_apk, aligned_apk], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=SUBPROCESS_FLAGS)

        cmd_sign = ["java", "-jar", "tools/apksigner.jar", "sign", "--ks", "tools/debug.keystore", "--ks-pass", "pass:android", aligned_apk]
        proc = subprocess.run(cmd_sign, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS)
        
        if proc.returncode == 0:
            self.log(f"\n--- SUCCESS! Production Modded Signed Target Ready Asset ready ---")
            self.update_task_state("Modded bundle recompiled and signed.", "success")
            if os.path.exists(unsigned_apk): os.remove(unsigned_apk)
        else:
            self.log("[-] Error: Signing parameter injection sequence was rejected.")
            self.update_task_state("Modded package cryptographic validation failed.", "failed")
        self.refresh_interface_locks()

    def start_ios_app_fetch(self):
        if not paramiko: return
        self.btn_fetch_apps.configure(state="disabled")
        self.update_task_state("[SSH] Auditing remote container directory spaces...", "running")
        threading.Thread(target=self.ios_fetch_apps_worker, daemon=True).start()

    def ios_fetch_apps_worker(self):
        ip = self.ent_ios_ip.get().strip(); user = self.ent_ios_user.get().strip(); password = self.ent_ios_pass.get()
        self.log(f"\n[*] Opening secure network transport layer: {user}@{ip}...")
        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(ip, username=user, password=password, timeout=10)
            cmd = (
                r'cd /var/containers/Bundle/Application/ && '
                r'for d in *; do '
                r'  if [ -d "$d" ]; then '
                r'    app=$(ls -d "$d"/*.app 2>/dev/null | head -n 1 | xargs basename); '
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
                        self.discovered_ios_apps[app_name.strip()] = (uuid.strip(), app_folder.strip())
                        app_names.append(app_name.strip())

            if app_names:
                self.cbo_ios_apps.configure(values=sorted(app_names))
                self.cbo_ios_apps.set(sorted(app_names)[0])
                self.log(f"[+] Synced {len(app_names)} live remote iOS application profiles.")
                self.update_task_state("iOS App bundles decrypted database synced.", "success")
            else:
                self.update_task_state("Zero valid decrypted containers located.", "failed")
        except Exception as e:
            self.log(f"[-] Transport Connection Failure: {str(e)}")
            self.update_task_state("SSH Authentication handshake failed.", "failed")
        finally:
            ssh.close(); self.btn_fetch_apps.configure(state="normal")

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
            temp_dir = os.path.join(self.ios_dest_dir, "ios_temp")
            payload_dir = os.path.join(temp_dir, "Payload")

            if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
            os.makedirs(payload_dir, exist_ok=True)

            with SCPClient(ssh.get_transport()) as scp: scp.get(remote_app_path, local_path=payload_dir, recursive=True)

            safe_filename = "".join(c for c in app_name if c.isalnum() or c in (" ", "_", "-")).strip()
            ipa_output_path = os.path.join(self.ios_dest_dir, f"{safe_filename}.ipa")

            with zipfile.ZipFile(ipa_output_path, "w", zipfile.ZIP_DEFLATED) as ipa_zip:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        full_fp = os.path.join(root, file)
                        ipa_zip.write(full_fp, os.path.relpath(full_fp, temp_dir))

            shutil.rmtree(temp_dir)
            self.log(f"\n--- SUCCESS! Final Production IPA Package Forged ---\n -> {ipa_output_path}")
            self.update_task_state("Decrypted IPA compiled successfully.", "success")
            messagebox.showinfo("Success", f"IPA built successfully:\n{ipa_output_path}")
        except Exception as e: 
            self.log(f"[-] Packaging workflow runtime fault: {str(e)}")
            self.update_task_state("Secure transport copy block sequence failure.", "failed")
        finally: ssh.close(); self.btn_build_ipa.configure(state="normal")


if __name__ == "__main__":
    try:
        print("[*] Spawning CustomTkinter Engine Window...")
        main_window = NKCyberSuiteMobile()
        main_window.mainloop()
        print("[+] Window closed cleanly.")
    except Exception as error:
        print(f"\n[-] ENGINE RUNTIME CRASH LOG:\n{error}\n")
        import traceback; traceback.print_exc()
