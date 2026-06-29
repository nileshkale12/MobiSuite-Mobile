# 💎 MobiSuite v1.0.0

MobiSuite is a cross-platform, multi-threaded GUI pipeline engine designed for mobile application security analysts, penetration testers, and reverse engineers. It replaces complex, repetitive command-line workflows with a streamlined, click-driven interface to automate the extraction, modification, assembly, signing, and deployment of Android (APK/APKS) and decrypted iOS (IPA) application binaries.

---

## 🚀 What Our Tool Does & How It Works

MobiSuite bridges the gap between raw command-line tools and modern GUI accessibility. Behind the scenes, it manages an asynchronous execution environment that safely orchestrates industry-standard utilities, ensuring your GUI never freezes while performing heavy cryptographic or file-system tasks. 

### 🛠️ Core Use Cases & Updated Features

* **Automated Reverse Engineering (Decompile & Rebuild):** 
  Instantly unpackages Android APK structures down to readable Smali source code, `AndroidManifest.xml` files, and raw assets using `apktool`. Once your security modifications are complete, the pipeline automatically rebuilds the directory back into an unsigned package.
* **Split APK Bundle Merging:** 
  Modern Android apps are often delivered as fragmented App Bundles (`base.apk` + DPI/Language config splits). MobiSuite natively calls `APKEditor` to seamlessly unify these multi-component architectures into a single standalone binary for frictionless static analysis.
* **Cryptographic Signing & Boundary Optimization:** 
  No need to memorize keystore passwords or alignment bytes. The suite automatically handles package byte-alignment via `zipalign` and applies certified debugging signatures using `apksigner` so the operating system accepts your modified package.
* **Advanced Native ADB Installer Console (NEW):** 
  Features a dedicated standalone console to sideload custom or rebuilt APKs directly to connected physical devices. It includes dynamic command presets for:
  * *Standard Installs* (`-r`)
  * *Force Downgrades* (`-d`) to bypass version constraint conflicts.
  * *Allow Test Apps* (`-t`) 
  * **Play Store Vending Spoofing** (`pm install -i com.android.vending`): Tricks the Android OS into believing the application was officially downloaded and licensed through the Google Play Store, effectively bypassing source-installation restrictions.
* **Decrypted iOS Storage Pulling & Smart Pathing (NEW):** 
  Creates a secure SSH tunnel to remote jailbroken iOS devices to locate, pull, and automatically forge decrypted `.app` containers into raw, distributable `.ipa` binaries. 
  * *String Sanitization Engine:* Automatically strips problematic escaped shell slashes and handles spaces in remote folder names (e.g., smoothly resolving `Apple\ Store.app`).
  * *Windows Long-Path Bypass:* Natively utilizes Windows Extended Paths (`\\?\`) to safely bypass the strict 260-character Windows folder limit during deep recursive file system pulls, preventing crashes when saving to nested OneDrive or enterprise project folders.
* **Live Environmental Auditing:** 
  Actively monitors connected physical hardware via background ADB/SSH transport loops, tracking device IDs and IP endpoints dynamically on a unified bottom HUD.

---

## 🔬 Technical Architecture & Specifications

### System Requirements
* **Supported OS:** Kali Linux / Ubuntu, Windows 10/11, macOS
* **Runtime Core:** Python 3.10+
* **Dependencies Node:** Java Runtime Environment (JRE) / JDK 8+ (Required for binary assembly and signing tools)

### Toolset Blueprint & Binaries Inventory
MobiSuite maps and isolates the following industry-standard utility binaries into a dedicated localized directory structure:

| Binary Component | Purpose / Specification | Integration Layer |
| :--- | :--- | :--- |
| `adb` | Android Debug Bridge subsystem connection loop & package sideloading | Hardware HUD & Installer Console |
| `apktool.jar` | Decodes resources to nearly original form and rebuilds them | Step 1 & 2 Android Pipeline |
| `APKEditor.jar` | Merges split bundle architectures (`base.apk` + configurations) | Step 0b Android Pipeline |
| `zipalign` | Provides crucial 4-byte boundary alignment optimizations for resources | Production Alignment Task |
| `apksigner.jar` | Signs APKs with v1, v2, v3, and v4 cryptographic validation schemes | Standalone & Mod Rebuild |

### Embedded Python Extensions
The following framework layers are validated and maintained automatically by the environment controller upon suite initialization:
* `customtkinter` — High-contrast premium UI rendering layer supporting scrollable window limits.
* `paramiko` — Low-level SSHv2 protocol transport channel management.
* `scp` — Secure Copy Protocol wrapper node for encrypted asset scraping and recursive network pulls.

## 🚀 Installation & Launch
```bash
🐉 In Kali Setup Guide

Step 1: Clone the Workspace In Kali with below cmd
      `git clone https://github.com/nileshkale12/MobiSuite-Mobile.git`

Step 2: Navigate to below dir
      `cd MobiSuite-Mobile`

Step 3: Install foundational platform tools
      `sudo apt update && sudo apt install default-jdk adb zipalign apksigner -y`

Step 4: Initialize Python required dependencies
      `python3 -m pip install customtkinter paramiko scp cryptography`

Step 5: Give permission to the below file to run the tool
      `chmod +x Launch_Kali.sh`

Step 6: Run the below command to launch the tool
      `./Launch_Kali.sh  or python3 auto_apk_1.0.py`

(Alternatively, run the suite directly using the interpreter: python3 auto_apk_1.0.py)

---

🪟 In Windows Setup Guide

Step 1: Ensure Prerequisites are Installed
Make sure your system has Python 3 and Java 17+ (JRE/JDK) installed and added to your system PATH. No Admin Access is required.

Step 2: Clone or download the Workspace
      `git clone https://github.com/nileshkale12/MobiSuite-Mobile.git`

Step 3: Navigate to the below directory
      `cd MobiSuite-Mobile`

Step 4: Initialize Python required dependencies Open your command prompt (cmd) inside the folder and run: 
      `python -m pip install customtkinter paramiko scp cryptography pyinstaller`

Step 5: Run the below command to launch the tool
Double-click the Launch_Windows.bat file to boot the Control Center, or run it directly in the terminal:
      `Launch_Windows.bat`
