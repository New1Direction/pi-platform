/*
 * linux-ipc.js  (RE / authorized-testing use only)
 *
 * Linux IPC/socket monitor for Electron AI IDEs. Richer companion to
 * electron-multiprocess-io.js: in addition to send/recv/write/read it hooks
 * sendmsg/recvmsg (scatter-gather IPC) and connect() to surface unix-domain
 * socket paths used between the renderer, helper processes and the language
 * server.
 *
 * Reports back as `dynamic-trace` messages:
 *     { hook: "sendmsg"|"recvmsg"|"send"|"recv"|"connect", preview: "<bytes>", size: N }
 *
 * __SELECTORS__ is accepted for a uniform render signature but unused here.
 */
'use strict';

const PREVIEW_BYTES = 64;

function preview(ptr, len) {
    try {
        const n = Math.min(len, PREVIEW_BYTES);
        if (n <= 0) return '';
        const bytes = Memory.readByteArray(ptr, n);
        return Array.from(new Uint8Array(bytes))
            .map(function (b) { return (b >= 32 && b < 127) ? String.fromCharCode(b) : '.'; })
            .join('');
    } catch (e) {
        return '';
    }
}

// simple buffer calls: send/recv/write/read (fd, buf, len, ...)
['send', 'recv', 'write', 'read'].forEach(function (fn) {
    const addr = Module.findExportByName(null, fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            const p = preview(args[1], args[2].toInt32());
            if (p) send({ hook: fn, preview: p, size: args[2].toInt32() });
        }
    });
});

// sendmsg/recvmsg: struct msghdr { ...; struct iovec* msg_iov; size_t msg_iovlen; ... }
// iovec { void* iov_base; size_t iov_len; }  (msg_iov at offset 2 pointers in on LP64)
['sendmsg', 'recvmsg'].forEach(function (fn) {
    const addr = Module.findExportByName(null, fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            try {
                const msghdr = args[1];
                const iov = msghdr.add(2 * Process.pointerSize).readPointer(); // msg_iov
                const base = iov.readPointer();                                // iov_base
                const len = iov.add(Process.pointerSize).readU32();            // iov_len (low word)
                const p = preview(base, len);
                if (p) send({ hook: fn, preview: p, size: len });
            } catch (e) { /* ignore */ }
        }
    });
});

// connect: surface unix-domain socket paths (sockaddr_un.sun_path at offset 2)
const connectAddr = Module.findExportByName(null, 'connect');
if (connectAddr) {
    Interceptor.attach(connectAddr, {
        onEnter: function (args) {
            try {
                const family = args[1].readU16();
                if (family === 1) { // AF_UNIX
                    const path = args[1].add(2).readUtf8String();
                    if (path) send({ hook: 'connect', preview: path, size: path.length });
                }
            } catch (e) { /* ignore */ }
        }
    });
}

send({ hook: 'linux-ipc', preview: '(installed)', size: 0 });
