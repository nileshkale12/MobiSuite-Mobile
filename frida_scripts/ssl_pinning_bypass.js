/*
 * Universal Android SSL/TLS pinning bypass.
 * Hooks the most common pinning implementations so intercepted traffic
 * (e.g. via mitmproxy) is trusted regardless of the app's pinning logic.
 * Intended for use only against apps you are authorized to test.
 */

function log(msg) {
    send("[SSL-BYPASS] " + msg);
}

Java.perform(function () {
    // ---------------------------------------------------------------
    // 1) OkHttp3 CertificatePinner.check(String, List<Certificate>)
    // ---------------------------------------------------------------
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        var overloads = CertificatePinner.check.overloads;
        overloads.forEach(function (overload) {
            overload.implementation = function () {
                log("okhttp3.CertificatePinner.check() bypassed for " + (arguments[0] || "<unknown host>"));
                return;
            };
        });
        log("Hooked okhttp3.CertificatePinner.check");
    } catch (e) {
        log("okhttp3.CertificatePinner not present: " + e.message);
    }

    // ---------------------------------------------------------------
    // 2) OkHttp3 CertificatePinner.check$okhttp (newer OkHttp releases)
    // ---------------------------------------------------------------
    try {
        var CertificatePinner2 = Java.use("okhttp3.CertificatePinner");
        if (CertificatePinner2["check\$okhttp"]) {
            CertificatePinner2["check\$okhttp"].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    log("okhttp3.CertificatePinner.check$okhttp() bypassed");
                    return;
                };
            });
            log("Hooked okhttp3.CertificatePinner.check$okhttp");
        }
    } catch (e) {}

    // ---------------------------------------------------------------
    // 3) Android platform TrustManagerImpl (used by nearly everything
    //    on top of javax.net.ssl, including most HTTP clients)
    // ---------------------------------------------------------------
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            log("TrustManagerImpl.verifyChain bypassed for host=" + host);
            return untrustedChain;
        };
        log("Hooked com.android.org.conscrypt.TrustManagerImpl.verifyChain");
    } catch (e) {
        log("TrustManagerImpl.verifyChain not present: " + e.message);
    }

    try {
        var TrustManagerImpl2 = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl2.checkTrustedRecursive.implementation = function () {
            log("TrustManagerImpl.checkTrustedRecursive bypassed");
            return Java.use("java.util.ArrayList").$new();
        };
        log("Hooked com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive");
    } catch (e) {}

    // ---------------------------------------------------------------
    // 4) Generic custom X509TrustManager implementations
    // ---------------------------------------------------------------
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManager = Java.registerClass({
            name: "com.mobisuite.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        log("Registered a permissive TrustAllManager (available for custom SSLContext hooks)");
    } catch (e) {
        log("Could not register TrustAllManager: " + e.message);
    }

    // ---------------------------------------------------------------
    // 5) HostnameVerifier - force all hostname checks to pass
    // ---------------------------------------------------------------
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.overload("javax.net.ssl.HostnameVerifier").implementation = function (verifier) {
            log("HttpsURLConnection.setDefaultHostnameVerifier call observed - leaving app verifier in place");
        };
    } catch (e) {}

    try {
        var HostnameVerifierClass = Java.use("javax.net.ssl.HostnameVerifier");
        var AllowAllHostnameVerifier = Java.registerClass({
            name: "com.mobisuite.AllowAllHostnameVerifier",
            implements: [HostnameVerifierClass],
            methods: {
                verify: function (hostname, session) { return true; }
            }
        });
        log("Registered AllowAllHostnameVerifier");
    } catch (e) {}

    // ---------------------------------------------------------------
    // 6) WebView SSL error handling
    // ---------------------------------------------------------------
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            log("WebViewClient.onReceivedSslError bypassed - proceeding despite SSL error");
            handler.proceed();
        };
        log("Hooked android.webkit.WebViewClient.onReceivedSslError");
    } catch (e) {
        log("WebViewClient.onReceivedSslError not present: " + e.message);
    }

    log("SSL pinning bypass hooks installed.");
});
