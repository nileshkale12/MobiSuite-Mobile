# 💎 MobiSuite v1.0.0

MobiSuite is a cross-platform, multi-threaded GUI pipeline engine designed for mobile application security analysts, penetration testers, and reverse engineers. It automates repetitive operational workflows involved in decompiling, modifying, merging, and signing Android (APK/APKS) and decrypted iOS (IPA) application binaries.

---

## 🛠️ Core Use Cases

* **Automated Reverse Engineering:** Instantly decompile APK structures down to readable Smali source configurations and assets without manual command inputs.
* **Split APK Bundle Merging:** Seamlessly unifies multi-component Android split architectures into a single standalone binary for frictionless analysis.
* **Cryptographic Signing & Optimization:** Automatically handles package byte-alignment via `zipalign` and applies certified debugging signatures using standard keystores.
* **Decrypted iOS Storage Pulling:** Remotely scans jailbroken iOS execution environments via secure network tunnels to stage and package container runtimes directly into distributable `.ipa` binaries.
* **Live Environmental Auditing:** Monitors connected physical devices via active ADB/SSH transport loops to query, pull, and track target packages dynamically on a single dashboard.

---

## 🔬 Technical Architecture & Specifications

### System Requirements
* **Supported OS:** Kali Linux / Ubuntu, Windows 10/11, macOS
* **Runtime Core:** Python 3.10+
* **Dependencies Node:** Java Runtime Environment (JRE) / JDK 8+ (Required for binary assembly tools)

### Toolset Blueprint & Binaries Inventory
MobiSuite maps and isolates the following industry-standard utility binaries into a dedicated localized directory structure:

| Binary Component | Purpose / Specification | Integration Layer |
| :--- | :--- | :--- |
| `adb` | Android Debug Bridge subsystem connection loop | Hardware Tracking HUD |
| `apktool.jar` | Decodes resources to nearly original form and rebuilds them | Step 1 & 2 Pipeline |
| `APKEditor.jar` | Merges split bundle architectures (`base.apk` + configurations) | Step 0b Pipeline |
| `zipalign` | Provides important boundary alignment optimizations for resource files | Production Alignment |
| `apksigner.jar` | Signs APKs with v1, v2, v3, and v4 cryptographic schemes | Standalone & Mod Rebuild |

### Embedded Python Extensions
The following framework layers are validated and maintained automatically by the environment controller upon suite initialization:
* `customtkinter` — High-contrast premium UI rendering layer.
* `paramiko` — Low-level SSHv2 protocol transport channel management.
* `scp` — Secure Copy Protocol wrapper node for encrypted asset scraping.

---

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
      git clone https://github.com/nileshkale12/MobiSuite-Mobile.git

Step 3: Navigate to the below directory
      cd MobiSuite-Mobile

Step 4: Initialize Python required dependencies Open your command prompt (cmd) inside the folder and run: 
      python -m pip install customtkinter paramiko scp cryptography pyinstaller

Step 5: Run the below command to launch the tool
Double-click the Launch_Windows.bat file to boot the Control Center, or run it directly in the terminal:
      Launch_Windows.bat
