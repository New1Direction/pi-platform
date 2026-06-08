/*
 * electron-multiprocess-io.js
 *
 * Generalized socket/IPC I/O monitor for multi-process Electron IDEs. Adapted
 * from cursor-re frida-templates (composer-network-hook.js,
 * full-composer-instrumentation.js). Hooks the libc I/O syscalls that carry
 * tool / agent / model traffic between the renderer, the helper processes and
 * the language server, and previews the payloads.
 *
 * Reports back as `dynamic-trace` messages:
 *     { hook: "send"|"recv"|"write"|"read", preview: "<first bytes>", size: N }
 *
 * The host may inject __SELECTORS__ but this template ignores it (kept for a
 * uniform render signature); it is included so multi-process IO can run
 * alongside the objc selector filter.
 */
'use strict';

const PREVIEW_BYTES = 64;

function preview(ptrArg, lenArg) {
    try {
        const len = lenArg.toInt32();
        if (len <= 0) return '';
        const n = Math.min(len, PREVIEW_BYTES);
        const bytes = Memory.readByteArray(ptrArg, n);
        return Array.from(new Uint8Array(bytes))
            .map(function (b) { return (b >= 32 && b < 127) ? String.fromCharCode(b) : '.'; })
            .join('');
    } catch (e) {
        return '';
    }
}

['send', 'recv', 'write', 'read'].forEach(function (fn) {
    const addr = Module.findExportByName(null, fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.buf = args[1];
            this.len = args[2];
        },
        onLeave: function (retval) {
            const p = preview(this.buf, this.len);
            if (p) {
                send({ hook: fn, preview: p, size: this.len.toInt32() });
            }
        }
    });
});

send({ hook: 'io', preview: '(installed)', size: 0 });
