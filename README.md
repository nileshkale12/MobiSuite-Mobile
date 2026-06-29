# 💎 MobiSuite v1.0.0

MobiSuite is a cross-platform, multi-threaded GUI pipeline engine designed for mobile application security analysts, penetration testers, and reverse engineers. It replaces complex, repetitive command-line workflows with a streamlined, click-driven interface to automate the extraction, modification, assembly, signing, and deployment of Android (APK/APKS) and decrypted iOS (IPA) application binaries.

![Downloads](https://img.shields.io/github/downloads/nileshkale12/MobiSuite-Mobile/total?style=for-the-badge&color=00E5FF)
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
```
🐉 In Kali Setup Guide

Step 1: Clone the Workspace In Kali with below cmd
      git clone https://github.com/nileshkale12/MobiSuite-Mobile.git

Step 2: Navigate to below dir
      cd MobiSuite-Mobile

Step 3: Install foundational platform tools
      sudo apt update && sudo apt install default-jdk adb zipalign apksigner -y

Step 4: Initialize Python required dependencies
      python3 -m pip install customtkinter paramiko scp cryptography

Step 5: Give permission to the below file to run the tool
      chmod +x Launch_Kali.sh

Step 6: Run the below command to launch the tool
      ./Launch_Kali.sh  or python3 auto_apk_1.0.py

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
      Launch_Windows.bat  or python3 auto_apk_1.0.py
```

## 📖 User Operations & Usage Guide

MobiSuite divides its capabilities into logical workflows. Follow these operational guidelines to run assessments on Android and iOS applications successfully.

### 🤖 1. Android Utilities Deck

#### **Step 0a: ADB Device Application Binary Puller**
* **What it does:** Extracts installed apps directly from a physical Android device over USB.
* **How to use it:**
  1. Connect your Android device with USB Debugging enabled. Verify the status turns green (`🟢 Connected`) in the bottom HUD bar.
  2. Click **Scan USB Apps**. The dropdown will populate with all third-party applications installed on the phone.
  3. Select your target app from the dropdown list and click **Pull Targets Folder**. Choose a folder on your computer to save the extracted packages.

#### **Step 0b: App Bundle Split Architecture Merger (Optional)**
* **What it does:** Combines split APK chunks (common in modern Play Store apps) into a single standalone APK file.
* **How to use it:**
  1. If Step 0a extracted multiple files (like `base.apk`, `split_config.apk`), click **Select Chunks Folder** and pick that extraction directory.
  2. Click **Merge via APKEditor**. The engine will compile them into a unified binary named `[FolderName]_merged.apk` and stage it as the active target.

#### **Step 1: Reverse Engineering Assembly Pipeline (Apktool)**
* **What it does:** Decompiles a single APK file into its component source files (Smali code, resources, images, layout XMLs).
* **How to use it:**
  1. Click **Browse Target APK** to manually load any APK, or let Step 0a/0b stage it automatically.
  2. Click **Decompile**. A new folder named `[AppName]_decompiled` will be created in the same directory. You can now open this folder in an external editor (like VS Code) to inspect code or modify security checks.

#### **Step 2: Package Compilation Reassembly & Jar Signer**
* **What it does:** Recompiles your modified project folder back into an optimized, fully signed, functional APK.
* **How to use it:**
  1. Click **Select Modded Folder** and choose your `_decompiled` directory (the tool verifies the presence of `apktool.yml`).
  2. Click **Rebuild & Sign**. The tool automatically triggers `apktool b`, optimizes alignment with `zipalign`, and signs it using a built-in debug signature profile to output a functional `*_MODDED.apk`.

#### **Step 3: Standalone Production Alignment & Signing Execution**
* **What it does:** Allows you to quickly optimize and cryptographically sign an existing unsigned APK without decompiling it first.
* **How to use it:**
  1. Click **Browse Manual APK** to select your raw unsigned application binary.
  2. Click **Zipalign & Sign** to instantly generate a standard, production-ready `*_SIGNED.apk`.

#### **Step 4: Standalone ADB Installation Engine**
* **What it does:** Sideloads any custom APK file onto your connected Android device with advanced parameters.
* **How to use it:**
  1. Click **Select Custom APK** to choose the file you want to push to the device.
  2. Select your desired deployment mode via the radio buttons:
     * **Standard Install (-r):** Reinstalls/replaces the app while preserving its local data.
     * **Force Downgrade (-d):** Bypasses version-checking blocks to force install an older package version over a newer one.
     * **Allow Test Apps (-t):** Allows deployment of applications marked as test packages in their manifests.
     * **Play Store Fake (-i Vending):** Deploys the package using a spoofed Google Play Store installation source configuration to bypass local application environment validation checks.
  3. *(Optional)* Modify the text in the **Custom Flag Override** entry field if you want to pass custom flags (e.g., adding a specific device signature handle).
  4. Click **Push Package to Device** to run the deployment thread.

---

### 🍏 2. iOS Utilities Deck

#### **Step 1: Jailbreak SSH Transport Link Context Parameters**
* **What it does:** Formulates an encrypted communication bridge to your jailbroken iOS device.
* **How to use it:**
  1. Ensure your iOS device is on the same local network as your workstation.
  2. Input the phone's local network IP address, SSH Username (default: `root`), and Password (default: `alpine`).
  3. Click **Scan App Bundles**. The tool securely tunnels into the filesystem to audit decrypted binary spaces.

#### **Step 2: Track Target Decrypted Bundle**
* **What it does:** Displays the tracked index of live apps pulled from the iOS device.
* **How to use it:**
  * Select your targeted mobile application from the dropdown menu. The application profiles map exact sandboxed directories automatically, keeping text clear of confusing backslashes or layout formatting errors.

#### **Step 3: Staging Automation & Local IPA Package Forging**
* **What it does:** Securely transfers decrypted iOS applications onto your desktop and compresses them safely into clean `.ipa` installation containers.
* **How to use it:**
  1. Click **Select Workpath Folder** to choose where the file should save.
  2. Click **Build Signed .ipa**. MobiSuite safely processes folder path structures using long-path support strings to download the binary blocks natively via SCP and compresses the bundle into a deployable application package.

---

### 📟 3. Live Terminal Logs & Settings

* **Live Terminal Logs Tab:** Open this dashboard tab at any time to inspect raw command-line stdout strings, active connection errors, sub-tool initialization lines, or script diagnostics.
* **Environment Settings Tab:** Check this screen to audit your local directory inventory setup status map. If an underlying binary component shows a red `🔴 MISSING` status badge, click **Force System Sync & Repair** to auto-download and repair the local repository environment block dependencies.
