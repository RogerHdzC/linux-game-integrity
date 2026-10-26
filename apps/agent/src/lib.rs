// SPDX-License-Identifier: Apache-2.0
//! Local observations; none of these reads proves integrity.
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};

pub const MAX_READ: usize = 1024 * 1024;
pub const MAX_ITEMS: usize = 4096;
pub const SECURE_BOOT: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadError {
    NotFound,
    PermissionDenied,
    InvalidData,
    TooLarge,
    Io,
}

impl From<io::Error> for ReadError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Io,
        }
    }
}

/// The live implementation only opens files for reading and queries metadata.
pub trait Source {
    fn origin(&self) -> Origin;
    fn read(&self, path: &str) -> Result<Vec<u8>, ReadError>;
    fn list(&self, path: &str) -> Result<Vec<String>, ReadError>;
    fn node(&self, path: &str) -> Result<bool, ReadError>;
    fn probe_read(&self, path: &str) -> Result<bool, ReadError>;
}

pub struct LinuxSource;

fn read_bounded(reader: impl Read) -> Result<Vec<u8>, ReadError> {
    let mut bytes = Vec::new();
    reader.take((MAX_READ + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_READ {
        return Err(ReadError::TooLarge);
    }
    Ok(bytes)
}

fn open_regular(path: &str) -> Result<File, ReadError> {
    // Avoid reading devices or FIFOs. Allow os-release/sysfs symlinks.
    if !fs::metadata(path)?.is_file() {
        return Err(ReadError::InvalidData);
    }
    Ok(File::open(path)?)
}

impl Source for LinuxSource {
    fn origin(&self) -> Origin {
        Origin::Live
    }
    fn read(&self, path: &str) -> Result<Vec<u8>, ReadError> {
        read_bounded(open_regular(path)?)
    }

    fn list(&self, path: &str) -> Result<Vec<String>, ReadError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(path)? {
            if names.len() >= MAX_ITEMS {
                return Err(ReadError::TooLarge);
            }
            names.push(
                entry?
                    .file_name()
                    .into_string()
                    .map_err(|_| ReadError::InvalidData)?,
            );
        }
        names.sort();
        Ok(names)
    }

    fn node(&self, path: &str) -> Result<bool, ReadError> {
        fs::metadata(path)?;
        Ok(true)
    }

    fn probe_read(&self, path: &str) -> Result<bool, ReadError> {
        // Probe a read of at most one byte, then discard it.
        // Do not export IMA paths or attempt to read an entire growing log.
        match open_regular(path)?.read(&mut [0u8; 1])? {
            0 | 1 => Ok(true),
            _ => Err(ReadError::Io),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation<T: Serialize> {
    pub status: &'static str,
    pub source: String,
    pub value: Option<T>,
    pub error: Option<ReadError>,
}

impl<T: Serialize> Observation<T> {
    fn new(source: &str, result: Result<T, ReadError>) -> Self {
        match result {
            Ok(value) => Self {
                status: "observed",
                source: source.into(),
                value: Some(value),
                error: None,
            },
            Err(error) => Self {
                status: if error == ReadError::NotFound {
                    "unavailable"
                } else {
                    "error"
                },
                source: source.into(),
                value: None,
                error: Some(error),
            },
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Distribution {
    pub id: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Module {
    pub name: String,
    pub size_bytes: u64,
    pub reference_count: i64,
    pub state: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tpm {
    pub class_devices: Observation<Vec<String>>,
    pub major_versions: Vec<Observation<u8>>,
    pub device_nodes: Vec<Observation<bool>>,
    pub command_access: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    pub distribution: Observation<Distribution>,
    pub kernel_release: Observation<String>,
    pub environment_hint: &'static str,
    pub secure_boot: Observation<&'static str>,
    pub tpm: Tpm,
    pub loaded_modules: Observation<Vec<Module>>,
    pub module_signature_enforcement: Observation<bool>,
    pub modules_disabled: Observation<bool>,
    pub lockdown: Observation<String>,
    pub kernel_taint: Observation<u64>,
    pub measurement_interfaces: Vec<Observation<bool>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub measurements_collected: bool,
    pub quote_present: bool,
    pub cryptographically_backed: bool,
    pub server_verified: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: u8,
    pub kind: &'static str,
    pub origin: Origin,
    pub trust: &'static str,
    pub agent_version: &'static str,
    pub platform: Platform,
    pub evidence: Evidence,
    pub result: &'static str,
    pub limitations: Vec<&'static str>,
}

fn text(source: &impl Source, path: &str) -> Result<String, ReadError> {
    let bytes = source.read(path)?;
    if bytes.len() > MAX_READ {
        return Err(ReadError::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_| ReadError::InvalidData)
}

fn bounded_string(value: &str) -> Result<String, ReadError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(ReadError::InvalidData)
    } else {
        Ok(value.into())
    }
}

// Parse assignments without executing a shell or expanding variables/commands.
fn os_value(raw: &str) -> Result<String, ReadError> {
    let raw = raw.trim();
    let value = if let Some(inner) = raw.strip_prefix('\'') {
        inner
            .strip_suffix('\'')
            .filter(|v| !v.contains('\''))
            .ok_or(ReadError::InvalidData)?
            .to_string()
    } else if let Some(inner) = raw.strip_prefix('"') {
        let inner = inner.strip_suffix('"').ok_or(ReadError::InvalidData)?;
        let mut chars = inner.chars();
        let mut result = String::new();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let next = chars.next().ok_or(ReadError::InvalidData)?;
                if !matches!(next, '$' | '`' | '"' | '\\') {
                    result.push('\\');
                }
                result.push(next);
            } else if matches!(c, '"' | '$' | '`') {
                return Err(ReadError::InvalidData);
            } else {
                result.push(c);
            }
        }
        result
    } else {
        if !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            return Err(ReadError::InvalidData);
        }
        raw.into()
    };
    if value.is_empty() {
        Ok(value)
    } else {
        bounded_string(&value)
    }
}

pub fn parse_distribution(input: &str) -> Result<Distribution, ReadError> {
    let mut values = BTreeMap::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(ReadError::InvalidData)?;
        if key == "ID" || key == "VERSION_ID" {
            values.insert(key, os_value(value)?);
        }
    }
    let id = values.remove("ID").ok_or(ReadError::InvalidData)?;
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-".contains(c))
    {
        return Err(ReadError::InvalidData);
    }
    Ok(Distribution {
        id,
        version_id: values.remove("VERSION_ID").filter(|v| !v.is_empty()),
    })
}

pub fn parse_secure_boot(bytes: &[u8]) -> Result<&'static str, ReadError> {
    // efivarfs prepends four attribute bytes to the UEFI UINT8 value.
    if bytes.len() != 5 {
        return Err(ReadError::InvalidData);
    }
    match bytes[4] {
        0 => Ok("disabled"),
        1 => Ok("enabled"),
        _ => Err(ReadError::InvalidData),
    }
}

pub fn parse_modules(input: &str) -> Result<Vec<Module>, ReadError> {
    let mut modules = Vec::new();
    for line in input.lines() {
        if modules.len() >= MAX_ITEMS {
            return Err(ReadError::TooLarge);
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6 {
            return Err(ReadError::InvalidData);
        }
        let name = bounded_string(fields[0])?;
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
        {
            return Err(ReadError::InvalidData);
        }
        let size_bytes = fields[1].parse().map_err(|_| ReadError::InvalidData)?;
        let reference_count: i64 = fields[2].parse().map_err(|_| ReadError::InvalidData)?;
        if reference_count < -1 || !matches!(fields[4], "Live" | "Loading" | "Unloading") {
            return Err(ReadError::InvalidData);
        }
        modules.push(Module {
            name,
            size_bytes,
            reference_count,
            state: fields[4].into(),
        });
    }
    Ok(modules)
}

fn flag(input: String) -> Result<bool, ReadError> {
    match input.trim() {
        "1" | "Y" => Ok(true),
        "0" | "N" => Ok(false),
        _ => Err(ReadError::InvalidData),
    }
}

pub fn parse_lockdown(input: &str) -> Result<String, ReadError> {
    let active: Vec<_> = input
        .split_whitespace()
        .filter(|s| s.starts_with('[') && s.ends_with(']'))
        .collect();
    if active.len() != 1 {
        return Err(ReadError::InvalidData);
    }
    match active[0] {
        "[none]" => Ok("none".into()),
        "[integrity]" => Ok("integrity".into()),
        "[confidentiality]" => Ok("confidentiality".into()),
        _ => Err(ReadError::InvalidData),
    }
}

pub fn collect(source: &impl Source) -> Report {
    let mut distro_path = "/etc/os-release";
    let mut distro = text(source, distro_path);
    if distro == Err(ReadError::NotFound) {
        distro_path = "/usr/lib/os-release";
        distro = text(source, distro_path);
    }
    let kernel_path = "/proc/sys/kernel/osrelease";
    let kernel = text(source, kernel_path).and_then(|v| bounded_string(v.trim()));
    let environment_hint = if kernel
        .as_ref()
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
    {
        "wsl"
    } else {
        "unknown"
    };
    let tpm_path = "/sys/class/tpm";
    let devices = source.list(tpm_path).and_then(|names| {
        if names.len() > MAX_ITEMS {
            return Err(ReadError::TooLarge);
        }
        Ok(names
            .into_iter()
            .filter(|n| {
                n.strip_prefix("tpm")
                    .map(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>())
    });
    let mut major_versions = Vec::new();
    let mut device_nodes = Vec::new();
    let mut node_names = vec!["/dev/tpm0".to_string(), "/dev/tpmrm0".to_string()];
    if let Ok(names) = &devices {
        for name in names {
            let path = format!("{tpm_path}/{name}/tpm_version_major");
            let version = text(source, &path).and_then(|s| match s.trim() {
                "1" => Ok(1),
                "2" => Ok(2),
                _ => Err(ReadError::InvalidData),
            });
            major_versions.push(Observation::new(&path, version));
            node_names.push(format!("/dev/{name}"));
            node_names.push(format!("/dev/tpmrm{}", &name[3..]));
        }
    }
    node_names.sort();
    node_names.dedup();
    for path in node_names {
        device_nodes.push(Observation::new(&path, source.node(&path)));
    }
    let interfaces = [
        "/sys/kernel/security/ima/ascii_runtime_measurements",
        "/sys/kernel/security/ima/binary_runtime_measurements",
        "/sys/kernel/security/ima/policy",
        "/sys/kernel/security/tpm0/binary_bios_measurements",
    ]
    .into_iter()
    .map(|path| Observation::new(path, source.probe_read(path)))
    .collect();
    let sig_path = "/sys/module/module/parameters/sig_enforce";
    let disabled_path = "/proc/sys/kernel/modules_disabled";
    let lockdown_path = "/sys/kernel/security/lockdown";
    let taint_path = "/proc/sys/kernel/tainted";
    Report {
        schema_version: 1, kind: "linux-inventory", origin: source.origin(), trust: "os-declared-unverified", agent_version: env!("CARGO_PKG_VERSION"),
        platform: Platform {
            distribution: Observation::new(distro_path, distro.and_then(|v| parse_distribution(&v))),
            kernel_release: Observation::new(kernel_path, kernel), environment_hint,
            secure_boot: Observation::new(SECURE_BOOT, source.read(SECURE_BOOT).and_then(|v| parse_secure_boot(&v))),
            tpm: Tpm { class_devices: Observation::new(tpm_path, devices), major_versions, device_nodes, command_access: "not-tested" },
            loaded_modules: Observation::new("/proc/modules", text(source, "/proc/modules").and_then(|v| parse_modules(&v))),
            module_signature_enforcement: Observation::new(sig_path, text(source, sig_path).and_then(flag)),
            modules_disabled: Observation::new(disabled_path, text(source, disabled_path).and_then(flag)),
            lockdown: Observation::new(lockdown_path, text(source, lockdown_path).and_then(|v| parse_lockdown(&v))),
            kernel_taint: Observation::new(taint_path, text(source, taint_path).and_then(|v| v.trim().parse().map_err(|_| ReadError::InvalidData))),
            measurement_interfaces: interfaces,
        },
        evidence: Evidence { measurements_collected: false, quote_present: false, cryptographically_backed: false, server_verified: false },
        result: "INDETERMINATE",
        limitations: vec![
            "OS-declared data; a compromised administrator or kernel can alter it.",
            "No PCR values, IMA logs or quotes are collected; no cryptographic verification or server evaluation occurs.",
            "TPM device-node existence does not prove command access, version, provenance or device trust.",
            "Unavailable interfaces may reflect permissions, mounts, containers, WSL or kernel configuration.",
            "The inventory is not atomic; individual reads may represent different moments.",
            "Does not prove absence of cheats or compatibility with Riot Vanguard or League of Legends.",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_read_rejects_oversize_without_truncating() {
        assert_eq!(
            read_bounded(vec![0; MAX_READ + 1].as_slice()),
            Err(ReadError::TooLarge)
        );
        assert_eq!(
            read_bounded(vec![0; MAX_READ].as_slice()).unwrap().len(),
            MAX_READ
        );
    }

    #[test]
    fn secure_boot_requires_attributes_and_boolean_payload() {
        assert_eq!(parse_secure_boot(&[7, 0, 0, 0, 1]), Ok("enabled"));
        assert_eq!(parse_secure_boot(&[7, 0, 0, 0, 0]), Ok("disabled"));
        for data in [&[1][..], &[7, 0, 0, 0, 2], &[7, 0, 0, 0, 1, 0]] {
            assert_eq!(parse_secure_boot(data), Err(ReadError::InvalidData));
        }
    }

    #[test]
    fn distro_parsing_supports_quotes_missing_version_and_last_assignment() {
        let d =
            parse_distribution("# test\nID=debian\nID=\"ubuntu\"\nVERSION_ID='24.04'\n").unwrap();
        assert_eq!(d.id, "ubuntu");
        assert_eq!(d.version_id.as_deref(), Some("24.04"));
        assert_eq!(parse_distribution("ID=rolling").unwrap().version_id, None);
        assert_eq!(os_value("\"a\\\"b\""), Ok("a\"b".into()));
    }

    #[test]
    fn distro_rejects_malformed_values_and_shell_expansion() {
        for input in [
            "VERSION_ID=1",
            "ID=\"ubuntu",
            "ID=$(id)",
            "ID=\"$(id)\"",
            "ID=UBUNTU",
            "ID=",
            "ID=ubuntu\nbroken",
        ] {
            assert!(parse_distribution(input).is_err(), "{input}");
        }
    }

    #[test]
    fn modules_omit_addresses_and_validate_numeric_data() {
        let m = parse_modules("test_mod 16384 0 - Live 0xffffffffdeadbeef\n").unwrap();
        assert_eq!(m[0].size_bytes, 16384);
        assert!(!serde_json::to_string(&m).unwrap().contains("deadbeef"));
        assert!(parse_modules("").unwrap().is_empty());
        for input in [
            "bad",
            "test abc 0 - Live 0x0",
            "test 1 -2 - Live 0x0",
            "test 1 0 - Weird 0x0",
        ] {
            assert!(parse_modules(input).is_err());
        }
    }

    #[test]
    fn lockdown_requires_one_recognized_active_mode() {
        assert_eq!(
            parse_lockdown("none [integrity] confidentiality\n"),
            Ok("integrity".into())
        );
        for input in ["none integrity", "[none] [integrity]", "[unknown]"] {
            assert!(parse_lockdown(input).is_err());
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Live,
    Synthetic,
}
