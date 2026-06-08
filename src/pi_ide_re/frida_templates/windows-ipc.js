/*
 * windows-ipc.js  (RE / authorized-testing use only)
 *
 * Windows IPC/socket monitor for Electron AI IDEs on Win32. Companion to
 * electron-multiprocess-io.js (posix). Hooks the kernel32 file/pipe I/O and
 * ws2_32 socket calls that carry tool/agent/model traffic between the renderer,
 * helper processes, the language server and named pipes.
 *
 * Reports back as `dynamic-trace` messages:
 *     { hook: "WriteFile"|"ReadFile"|"WSASend"|"WSARecv", preview: "<bytes>", size: N }
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

// kernel32: WriteFile/ReadFile (covers files AND named pipes \\.\pipe\*)
[['WriteFile', 'kernel32.dll'], ['ReadFile', 'kernel32.dll']].forEach(function (entry) {
    const addr = Module.findExportByName(entry[1], entry[0]);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            // BOOL WriteFile(HANDLE, LPCVOID lpBuffer, DWORD nBytes, ...)
            const p = preview(args[1], args[2].toInt32());
            if (p) send({ hook: entry[0], preview: p, size: args[2].toInt32() });
        }
    });
});

// ws2_32: WSASend/WSARecv (WSABUF { ULONG len; CHAR* buf; })
[['WSASend', 'ws2_32.dll'], ['WSARecv', 'ws2_32.dll']].forEach(function (entry) {
    const addr = Module.findExportByName(entry[1], entry[0]);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            try {
                const wsabuf = args[1];                       // first WSABUF*
                const len = wsabuf.readU32();                 // ULONG len
                const buf = wsabuf.add(Process.pointerSize).readPointer(); // CHAR* buf
                const p = preview(buf, len);
                if (p) send({ hook: entry[0], preview: p, size: len });
            } catch (e) { /* ignore */ }
        }
    });
});

send({ hook: 'win-ipc', preview: '(installed)', size: 0 });
