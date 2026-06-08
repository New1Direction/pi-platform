/*
 * electron-objc-selector-filter.js
 *
 * Generalized objc_msgSend selector filter for Electron-based AI IDEs
 * (Cursor / Windsurf / Antigravity / VSCode forks). Adapted from the
 * cursor-re frida-templates (cursor-main-process-hook.js).
 *
 * The host injects __SELECTORS__ (a JSON array of keyword substrings). Every
 * Objective-C selector whose name contains one of those keywords is reported
 * back to the host as a structured `dynamic-trace` message:
 *     { hook: "objc_msgSend", selector: "<sel>", keyword: "<kw>" }
 *
 * This keeps the analysis output machine-ingestable (graph nodes) rather than
 * console noise.
 */
'use strict';

const SELECTORS = __SELECTORS__;

function matchKeyword(sel) {
    for (let i = 0; i < SELECTORS.length; i++) {
        if (sel.indexOf(SELECTORS[i]) !== -1) {
            return SELECTORS[i];
        }
    }
    return null;
}

const objc_msgSend = Module.findExportByName(null, 'objc_msgSend');
if (objc_msgSend && typeof ObjC !== 'undefined' && ObjC.available) {
    Interceptor.attach(objc_msgSend, {
        onEnter: function (args) {
            try {
                const sel = ObjC.selectorAsString(args[1]);
                if (!sel) return;
                const kw = matchKeyword(sel);
                if (kw) {
                    send({ hook: 'objc_msgSend', selector: sel, keyword: kw });
                }
            } catch (e) {
                // selector not resolvable; ignore
            }
        }
    });
    send({ hook: 'objc_msgSend', selector: '(installed)', keyword: '(installed)' });
} else {
    send({ hook: 'objc_msgSend', selector: '(unavailable)', keyword: '(unavailable)' });
}
