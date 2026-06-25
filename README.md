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

### 1. Clone the Workspace
```bash
git clone [https://github.com/nileshkale12/NK-CyberSuite-Mobile.git](https://github.com/nileshkale12/NK-CyberSuite-Mobile.git)
cd NK-CyberSuite-Mobile

## 🛠️ Features & Capabilities

* **Automated Extraction**: Pull application binaries directly from connected physical devices via high-speed ADB.
* **Environment Integrity Sync**: Integrated multi-threaded backend scanner automatically checks, downloads, and patches necessary dependencies (Apktool, APKEditor, zipalign, apksigner).
* **Multi-Format Assembly**: Seamlessly merge split Android app bundles into monolithic structures, recompile, optimize with 4-byte boundary alignment, and sign packages.
* **Jailbroken iOS Linkage**: Integrated paramiko and secure SCP transport loops to scan, read application names via remote Plist queries, pull application directories, and forge valid `.ipa` packages.

---

## 🚀 Quick Launch Guide

### 🪟 Windows Deployment (No Admin Access Required)
1. Ensure your system has **Python 3** and **Java 17+ (JRE/JDK)** installed.
2. Clone or download this repository onto your machine.
3. Open a command prompt (`cmd`) inside the project folder and run:

   python -m pip install customtkinter paramiko scp cryptography pyinstaller

4. Double-click Launch_Windows.bat to boot the Control Center!

### 🐉 Kali Linux Deployment

1. Clone the suite and enter the directory:
 git clone [https://github.com/nileshkale12/NK-CyberSuite-Mobile.git](https://github.com/nileshkale12/NK-CyberSuite-Mobile.git)
   cd NK-CyberSuite-Mobile

2. Install foundational platform tools: 
 sudo apt update && sudo apt install default-jdk adb zipalign apksigner -y

3. Initialize Python required dependencies:
  python3 -m pip install customtkinter paramiko scp cryptography

4. Run the suite natively using the interpreter: 
  python3 auto_apk_v4.py






