//! Small helpers shared by the rest of the crate.

use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Rename `temp` onto `target`, replacing an existing file on every platform
/// (Windows `rename` refuses to overwrite).
pub fn replace_file(temp: &Path, target: &Path) -> io::Result<()> {
    match fs::rename(temp, target) {
        Ok(()) => Ok(()),
        Err(err) => {
            if target.exists() {
                fs::remove_file(target)?;
                fs::rename(temp, target)
            } else {
                Err(err)
            }
        }
    }
}

/// Write a file atomically (temp file in the same directory + rename).
pub fn atomic_write(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = path.with_file_name(format!(".{file_name}.psync.tmp"));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            options.mode(0o600);
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        }
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    replace_file(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
pub fn set_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn set_private(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub fn expand_tilde(value: &str) -> PathBuf {
    let trimmed = value.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    if trimmed == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(trimmed)
}

/// Normalise IPv4-mapped IPv6 addresses so gate/session keys are stable.
pub fn norm_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Validate a bundle-relative path such as `cindy-bots/owner/bots/x/SOUL.md`.
/// Returns the normalised relative path when it is safe to join onto a root.
pub fn safe_relative_path(raw: &str) -> Option<PathBuf> {
    if raw.is_empty() || raw.len() > 1024 || raw.contains('\0') || raw.contains('\\') {
        return None;
    }
    if raw.starts_with('/') || raw.contains(':') {
        return None;
    }
    let path = Path::new(raw);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_string_lossy();
                if part.is_empty() || part == "." || part == ".." || part == ".psync.tmp" {
                    return None;
                }
                if part.ends_with(".psync.tmp") {
                    return None;
                }
                out.push(part.as_ref());
            }
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Quote a string as a TOML basic string (for `set_value`).
pub fn toml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn human_age(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m{}s", seconds / 60, seconds % 60)
    } else if seconds < 86_400 {
        format!("{}h{}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d{}h", seconds / 86_400, (seconds % 86_400) / 3600)
    }
}

pub fn parse_host_port(value: &str, default_port: u16) -> Result<(String, u16), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty address".to_string());
    }
    // Bracketed IPv6: [::1]:1234
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("invalid address: {value}"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse::<u16>()
                .map_err(|_| format!("invalid port in {value}"))?,
            None => default_port,
        };
        return Ok((host.to_string(), port));
    }
    if value.matches(':').count() == 1 {
        let (host, port) = value.rsplit_once(':').expect("count checked");
        if host.is_empty() {
            return Err(format!("invalid address: {value}"));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("invalid port in {value}"))?;
        return Ok((host.to_string(), port));
    }
    Ok((value.to_string(), default_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_are_validated() {
        assert!(safe_relative_path("a/b/c.md").is_some());
        assert!(safe_relative_path("../etc/passwd").is_none());
        assert!(safe_relative_path("/etc/passwd").is_none());
        assert!(safe_relative_path("a/../../b").is_none());
        assert!(safe_relative_path("a\\b").is_none());
        assert!(safe_relative_path("C:/x").is_none());
        assert!(safe_relative_path("").is_none());
        assert!(safe_relative_path(".hidden.psync.tmp").is_none());
    }

    #[test]
    fn host_port_parsing() {
        assert_eq!(
            parse_host_port("example.com:1", 2).unwrap(),
            ("example.com".into(), 1)
        );
        assert_eq!(
            parse_host_port("example.com", 2).unwrap(),
            ("example.com".into(), 2)
        );
        assert_eq!(parse_host_port("[::1]:9", 2).unwrap(), ("::1".into(), 9));
        assert!(parse_host_port("example.com:nope", 2).is_err());
    }

    #[test]
    fn normalises_mapped_ipv6() {
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(norm_ip(mapped), "10.0.0.1".parse::<IpAddr>().unwrap());
    }
}
