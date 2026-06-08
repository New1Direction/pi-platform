/*
 * ssl-pinning-bypass.js  (RE / authorized-testing use only)
 *
 * Adapted from KikkaSkills/analysis/frida/scripts/ssl-pinning-bypass.js. Lets a
 * man-in-the-middle proxy observe an IDE's TLS traffic during authorized
 * reverse engineering by neutralizing certificate validation on macOS/iOS.
 *
 * Reports a single structured message so the host can record that pinning was
 * bypassed for this session:
 *     { hook: "ssl", event: "pinning-bypassed", api: "SecTrustEvaluate..." }
 */
'use strict';

['SecTrustEvaluate', 'SecTrustEvaluateWithError'].forEach(function (sym) {
    const addr = Module.findExportByName('Security', sym);
    if (!addr) return;
    Interceptor.attach(addr, {
        onLeave: function (retval) {
            // SecTrustEvaluate -> errSecSuccess(0); WithError -> true(1)
            retval.replace(sym === 'SecTrustEvaluate' ? ptr(0) : ptr(1));
            send({ hook: 'ssl', event: 'pinning-bypassed', api: sym });
        }
    });
});
