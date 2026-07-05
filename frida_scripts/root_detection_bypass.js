/*
 * Root / jailbreak detection bypass for common Android root-check techniques.
 * Intended for use only against apps you are authorized to test.
 */

function log(msg) {
    send("[ROOT-BYPASS] " + msg);
}

var ROOT_PACKAGE_NAMES = [
    "com.topjohnwu.magisk", "com.noshufou.android.su", "com.noshufou.android.su.elite",
    "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.thirdparty.superuser",
    "com.yellowes.su", "com.kingroot.kinguser", "com.kingo.root", "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global", "com.alephzain.framaroot"
];

var ROOT_BINARY_PATHS = [
    "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
    "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
    "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
    "/system/xbin/busybox", "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
    "/system/xbin/mu", "/data/adb/magisk"
];

Java.perform(function () {
    // ---------------------------------------------------------------
    // 1) File.exists() - deny knowledge of common su/root paths
    // ---------------------------------------------------------------
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            var isRootPath = ROOT_BINARY_PATHS.some(function (p) { return path.indexOf(p) !== -1; });
            if (isRootPath) {
                log("File.exists() spoofed to false for: " + path);
                return false;
            }
            return this.exists();
        };
        log("Hooked java.io.File.exists");
    } catch (e) {
        log("Could not hook File.exists: " + e.message);
    }

    // ---------------------------------------------------------------
    // 2) Runtime.exec() - block common root/su probing commands
    // ---------------------------------------------------------------
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var overloads = Runtime.exec.overloads;
        overloads.forEach(function (overload) {
            overload.implementation = function () {
                var cmd = arguments[0];
                var cmdStr = "";
                try {
                    cmdStr = (typeof cmd === "string") ? cmd : cmd.join(" ");
                } catch (e) { cmdStr = String(cmd); }
                if (cmdStr.indexOf("su") !== -1 || cmdStr.indexOf("busybox") !== -1 || cmdStr.indexOf("magisk") !== -1) {
                    log("Runtime.exec() blocked for suspicious command: " + cmdStr);
                    throw Java.use("java.io.IOException").$new("Command not found");
                }
                return overload.apply(this, arguments);
            };
        });
        log("Hooked java.lang.Runtime.exec");
    } catch (e) {
        log("Could not hook Runtime.exec: " + e.message);
    }

    // ---------------------------------------------------------------
    // 3) PackageManager checks for known root-manager packages
    // ---------------------------------------------------------------
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (packageName, flags) {
            if (ROOT_PACKAGE_NAMES.indexOf(packageName) !== -1) {
                log("PackageManager.getPackageInfo() spoofed NameNotFoundException for: " + packageName);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(packageName);
            }
            return this.getPackageInfo(packageName, flags);
        };
        log("Hooked android.app.ApplicationPackageManager.getPackageInfo");
    } catch (e) {
        log("Could not hook PackageManager.getPackageInfo: " + e.message);
    }

    // ---------------------------------------------------------------
    // 4) Build.TAGS - hide "test-keys" (common RootBeer-style check)
    // ---------------------------------------------------------------
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        log("Spoofed android.os.Build.TAGS to release-keys");
    } catch (e) {
        log("Could not spoof Build.TAGS: " + e.message);
    }

    // ---------------------------------------------------------------
    // 5) System.getenv("PATH") - strip root-ish directories
    // ---------------------------------------------------------------
    try {
        var System_ = Java.use("java.lang.System");
        System_.getenv.overload("java.lang.String").implementation = function (name) {
            var value = this.getenv(name);
            if (name === "PATH" && value) {
                var cleaned = value.split(":").filter(function (p) {
                    return p.indexOf("xbin") === -1 && p.indexOf("sbin") === -1;
                }).join(":");
                log("System.getenv(PATH) sanitized");
                return cleaned;
            }
            return value;
        };
        log("Hooked java.lang.System.getenv");
    } catch (e) {
        log("Could not hook System.getenv: " + e.message);
    }

    log("Root detection bypass hooks installed.");
});
