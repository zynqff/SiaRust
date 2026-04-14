// guardlib_node.js — Node.js integration for GuardLib
//
// npm install ffi-napi ref-napi
//
// Usage:
//   const { GuardLib } = require('./guardlib_node');
//   const guard = new GuardLib();
//   guard.initialize();
//   const config = guard.verifyConfig(configJson, sigBase64);

'use strict';

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const path = require('path');
const os = require('os');
const fs = require('fs');

function getLibPath() {
    const names = { linux: 'libguardlib.so', darwin: 'libguardlib.dylib', win32: 'guardlib.dll' };
    const name = names[os.platform()];
    if (!name) throw new Error(`Unsupported platform: ${os.platform()}`);
    const local = path.join(__dirname, name);
    if (fs.existsSync(local)) return local;
    return name; // try system path
}

function loadLib() {
    return ffi.Library(getLibPath(), {
        'guard_init':                 ['pointer', []],
        'guard_destroy':              ['void',    ['pointer']],
        'guard_verify_config':        ['string',  ['pointer', 'pointer', 'size_t', 'pointer', 'size_t']],
        'guard_validate_certificate': ['int',     ['pointer', 'pointer', 'size_t', 'string']],
        'guard_last_error':           ['string',  []],
        'guard_free_string':          ['void',    ['string']],
        'guard_version':              ['string',  []],
    });
}

class GuardLib {
    constructor() {
        this._lib = loadLib();
        this._handle = null;
    }

    /** Initialize GuardLib. Throws on detection or error. */
    initialize() {
        const version = this._lib.guard_version();
        console.log(`[GuardLib] Version: ${version}`);

        const handle = this._lib.guard_init();
        if (handle.isNull()) {
            const err = this._lib.guard_last_error() || 'Unknown error';
            throw new Error(`guard_init failed: ${err}`);
        }

        this._handle = handle;
        console.log('[GuardLib] ✅ Initialized');
    }

    /**
     * Verify signed config.
     * @param {string} configJson - Raw config.json content
     * @param {string} sigBase64  - Base64-encoded signature
     * @returns {{ apiUrl: string, apiFingerprint: string } | null}
     */
    verifyConfig(configJson, sigBase64) {
        this._assertInitialized();

        const jsonBuf = Buffer.from(configJson, 'utf8');
        const sigBuf  = Buffer.from(sigBase64.trim(), 'base64');

        if (sigBuf.length !== 64) {
            console.error(`[GuardLib] Signature wrong length: ${sigBuf.length}`);
            return null;
        }

        const resultStr = this._lib.guard_verify_config(
            this._handle,
            jsonBuf, jsonBuf.length,
            sigBuf, sigBuf.length,
        );

        if (!resultStr) {
            const err = this._lib.guard_last_error() || 'unknown';
            console.error(`[GuardLib] ❌ verifyConfig failed: ${err}`);
            return null;
        }

        try {
            const parsed = JSON.parse(resultStr);
            return { apiUrl: parsed.api_url, apiFingerprint: parsed.api_fingerprint };
        } catch (e) {
            console.error(`[GuardLib] Failed to parse result: ${e}`);
            return null;
        }
    }

    /**
     * Validate certificate fingerprint.
     * @param {Buffer} certDer    - Raw DER bytes
     * @param {string} expectedFp - Uppercase hex fingerprint
     * @returns {boolean}
     */
    validateCertificate(certDer, expectedFp) {
        this._assertInitialized();
        const result = this._lib.guard_validate_certificate(
            this._handle, certDer, certDer.length, expectedFp
        );
        if (result === 1) return true;
        if (result === 0) return false;
        const err = this._lib.guard_last_error() || 'unknown';
        console.error(`[GuardLib] Internal error: ${err}`);
        return false;
    }

    destroy() {
        if (this._handle) {
            this._lib.guard_destroy(this._handle);
            this._handle = null;
        }
    }

    _assertInitialized() {
        if (!this._handle) throw new Error('GuardLib not initialized');
    }
}

module.exports = { GuardLib };
