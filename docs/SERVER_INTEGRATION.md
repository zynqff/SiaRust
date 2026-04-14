# Server Integration Guide

GuardLib can run server-side to verify that signed configs are valid before serving them, or to validate certificates in proxy scenarios.

---

## Python

**Requirements:** `libguardlib.so` (Linux) or `libguardlib.dylib` (macOS) in same directory.

### Install

No pip packages needed — uses Python's built-in `ctypes`.

```bash
cp dist/linux/libguardlib.so your_project/
cp examples/python/guardlib_python.py your_project/
```

### Usage

```python
from guardlib_python import GuardLib

guard = GuardLib()
guard.initialize()

# Verify a config
with open("config.json") as f:
    config_json = f.read()
with open("config.sig") as f:
    sig_b64 = f.read().strip()

config = guard.verify_config(config_json, sig_b64)
if config:
    print(f"Valid. API URL: {config.api_url}")
    print(f"Fingerprint: {config.api_fingerprint}")
else:
    print("Invalid config or signature")

guard.destroy()
```

### FastAPI middleware example

```python
from fastapi import FastAPI, HTTPException
from guardlib_python import GuardLib

app = FastAPI()
guard = GuardLib()
guard.initialize()

@app.get("/verify-config")
async def verify_config(config_json: str, sig_b64: str):
    result = guard.verify_config(config_json, sig_b64)
    if result is None:
        raise HTTPException(status_code=400, detail="Config verification failed")
    return {"api_url": result.api_url, "api_fingerprint": result.api_fingerprint}
```

---

## Node.js

**Requirements:** `ffi-napi`, `ref-napi`

```bash
npm install ffi-napi ref-napi
cp dist/linux/libguardlib.so your_project/
cp examples/node/guardlib_node.js your_project/
```

### Usage

```javascript
const { GuardLib } = require('./guardlib_node');
const fs = require('fs');

const guard = new GuardLib();
guard.initialize();

const configJson = fs.readFileSync('config.json', 'utf8');
const sigBase64  = fs.readFileSync('config.sig', 'utf8').trim();

const config = guard.verifyConfig(configJson, sigBase64);
if (config) {
    console.log('Valid:', config.apiUrl);
} else {
    console.error('Invalid config');
}

guard.destroy();
```

### Express middleware

```javascript
const express = require('express');
const { GuardLib } = require('./guardlib_node');

const app = express();
const guard = new GuardLib();
guard.initialize();

app.post('/verify-config', express.json(), (req, res) => {
    const { config_json, sig_base64 } = req.body;
    const result = guard.verifyConfig(config_json, sig_base64);
    if (!result) {
        return res.status(400).json({ error: 'Verification failed' });
    }
    res.json({ api_url: result.apiUrl, api_fingerprint: result.apiFingerprint });
});
```

---

## Linux systemd service

For long-running server processes, initialize GuardLib once at startup:

```python
# server.py
import signal
from guardlib_python import GuardLib

guard = GuardLib()
guard.initialize()

def cleanup(signum, frame):
    guard.destroy()
    exit(0)

signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

# ... your server code
```

---

## Windows

```python
# Windows: place guardlib.dll next to script
# No other changes needed — guardlib_python.py detects platform automatically
guard = GuardLib()
guard.initialize()
```

---

## Notes for server use

- On Linux/macOS servers, root and Frida checks still run at `guard_init()`. They will pass cleanly on a normal server.
- The self-integrity check is most meaningful on mobile. On servers, set `INTEGRITY_CHECK_DISABLED = true` unless you specifically need it.
- GuardLib is stateless and thread-safe for `guard_verify_config()` and `guard_validate_certificate()`. The handle can be shared across threads.
- `guard_last_error()` is **thread-local** — check it on the same thread that called the failing function.
