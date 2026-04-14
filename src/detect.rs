/*
 * Runtime threat detection module.
 *
 * Detects:
 *   - Frida (gadget, server, named pipes, port 27042)
 *   - Root indicators (Magisk, su binary, known paths)
 *   - Debugger attachment
 *
 * Returns DetectionResult with a description of what was found.
 * Rust DOES NOT terminate the app — it returns the result to the caller.
 */

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub detected: bool,
    pub reason: String,
}

impl DetectionResult {
    pub fn clean() -> Self {
        Self { detected: false, reason: String::new() }
    }

    pub fn found(reason: &str) -> Self {
        Self { detected: true, reason: reason.to_string() }
    }
}

/// Run all detections. Returns first match found, or clean result.
pub fn run_all_checks() -> DetectionResult {
    #[cfg(target_os = "android")]
    {
        if let Some(r) = check_frida_android() { return r; }
        if let Some(r) = check_root_android() { return r; }
        if let Some(r) = check_debugger() { return r; }
    }

    #[cfg(target_os = "ios")]
    {
        if let Some(r) = check_frida_ios() { return r; }
        if let Some(r) = check_jailbreak_ios() { return r; }
        if let Some(r) = check_debugger() { return r; }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        // Desktop/server: only debugger check
        if let Some(r) = check_debugger() { return r; }
    }

    DetectionResult::clean()
}

// ── Android ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "android")]
fn check_frida_android() -> Option<DetectionResult> {
    // Check Frida named pipe (classic gadget indicator)
    let frida_paths = [
        "/proc/net/unix",
    ];

    for path in &frida_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if content.contains("frida") || content.contains("gum-js") || content.contains("linjector") {
                return Some(DetectionResult::found("Frida: detected in /proc/net/unix"));
            }
        }
    }

    // Check Frida port 27042
    if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
        // Port 27042 = 0x699A in hex, little-endian in /proc/net/tcp = 9A69
        if content.contains("9A69") {
            return Some(DetectionResult::found("Frida: port 27042 open"));
        }
    }
    if let Ok(content) = std::fs::read_to_string("/proc/net/tcp6") {
        if content.contains("9A69") {
            return Some(DetectionResult::found("Frida: port 27042 open (tcp6)"));
        }
    }

    // Check for frida-agent in /proc/self/maps
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let indicators = ["frida", "gum-js-loop", "linjector", "re.frida"];
        for ind in &indicators {
            if maps.contains(ind) {
                return Some(DetectionResult::found(&format!("Frida: '{}' in /proc/self/maps", ind)));
            }
        }
    }

    None
}

#[cfg(target_os = "android")]
fn check_root_android() -> Option<DetectionResult> {
    let su_paths = [
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
    ];

    for path in &su_paths {
        if std::path::Path::new(path).exists() {
            return Some(DetectionResult::found(&format!("Root: su binary at {}", path)));
        }
    }

    let magisk_paths = [
        "/sbin/.magisk",
        "/dev/.magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.img",
        "/cache/.disable_selinux",
        "/dev/magisk_debug",
    ];

    for path in &magisk_paths {
        if std::path::Path::new(path).exists() {
            return Some(DetectionResult::found(&format!("Root: Magisk indicator at {}", path)));
        }
    }

    // Check if /system is writable (should never be on stock)
    let test_path = "/system/.guardlib_rw_test";
    if std::fs::write(test_path, b"x").is_ok() {
        let _ = std::fs::remove_file(test_path);
        return Some(DetectionResult::found("Root: /system is writable"));
    }

    None
}

// ── iOS ──────────────────────────────────────────────────────────────────────

#[cfg(target_os = "ios")]
fn check_frida_ios() -> Option<DetectionResult> {
    // Frida writes to /tmp on iOS
    let frida_files = [
        "/tmp/frida-server",
        "/usr/lib/frida",
        "/usr/share/frida",
    ];
    for path in &frida_files {
        if std::path::Path::new(path).exists() {
            return Some(DetectionResult::found(&format!("Frida: found at {}", path)));
        }
    }
    None
}

#[cfg(target_os = "ios")]
fn check_jailbreak_ios() -> Option<DetectionResult> {
    let jb_paths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/sh",
        "/usr/libexec/ssh-keysign",
        "/etc/ssh/sshd_config",
        "/usr/libexec/sftp-server",
        "/usr/bin/sshd",
        "/usr/local/bin/cycript",
        "/usr/bin/cycript",
    ];

    for path in &jb_paths {
        if std::path::Path::new(path).exists() {
            return Some(DetectionResult::found(&format!("Jailbreak: found at {}", path)));
        }
    }

    // Try writing outside sandbox
    let test_path = "/private/guardlib_jb_test";
    if std::fs::write(test_path, b"x").is_ok() {
        let _ = std::fs::remove_file(test_path);
        return Some(DetectionResult::found("Jailbreak: can write outside sandbox"));
    }

    None
}

// ── Debugger (cross-platform) ─────────────────────────────────────────────────

fn check_debugger() -> Option<DetectionResult> {
    #[cfg(target_os = "android")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(pid_str) = parts.get(1) {
                        if let Ok(pid) = pid_str.parse::<i32>() {
                            if pid != 0 {
                                return Some(DetectionResult::found(
                                    &format!("Debugger: TracerPid={}", pid)
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
