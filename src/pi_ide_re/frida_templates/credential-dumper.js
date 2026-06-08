/*
 * credential-dumper.js  (RE / authorized-testing use only)
 *
 * Adapted from KikkaSkills/analysis/frida/scripts/credential-dumper.js for IDE
 * auth reverse engineering: surfaces where an AI IDE stores OAuth / session /
 * API-key material (macOS Keychain, NSUserDefaults). Reports each observation
 * back to the host as a structured message:
 *     { hook: "credential", source: "keychain"|"nsuserdefaults",
 *       key: "<service/account or defaults key>", value: "<raw>", type: "<class>" }
 *
 * The host-side CredentialFlowStage REDACTS `value` to a one-way fingerprint
 * before anything is persisted - raw secrets never reach the graph.
 */
'use strict';

const SENSITIVE = ['token', 'password', 'secret', 'key', 'auth', 'credential', 'session', 'oauth'];

function looksSensitive(name) {
    const n = (name || '').toLowerCase();
    return SENSITIVE.some(function (s) { return n.indexOf(s) !== -1; });
}

if (typeof ObjC !== 'undefined' && ObjC.available) {
    // Keychain: SecItemAdd / SecItemCopyMatching
    ['SecItemAdd', 'SecItemCopyMatching'].forEach(function (sym) {
        const addr = Module.findExportByName('Security', sym);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    const dict = new ObjC.Object(args[0]);
                    const svce = dict.objectForKey_ ? dict.objectForKey_('svce') : null;
                    const acct = dict.objectForKey_ ? dict.objectForKey_('acct') : null;
                    const data = dict.objectForKey_ ? dict.objectForKey_('v_Data') : null;
                    send({
                        hook: 'credential',
                        source: 'keychain',
                        key: '' + (svce ? svce : '?') + '/' + (acct ? acct : '?'),
                        value: data ? data.toString() : '',
                        type: 'keychain'
                    });
                } catch (e) { /* ignore */ }
            }
        });
    });

    // NSUserDefaults objectForKey:
    try {
        const NSUserDefaults = ObjC.classes.NSUserDefaults;
        Interceptor.attach(NSUserDefaults['- objectForKey:'].implementation, {
            onEnter: function (args) {
                try {
                    const k = new ObjC.Object(args[2]).toString();
                    if (looksSensitive(k)) {
                        send({ hook: 'credential', source: 'nsuserdefaults', key: k, value: '', type: 'defaults' });
                    }
                } catch (e) { /* ignore */ }
            }
        });
    } catch (e) { /* class not present */ }
}
