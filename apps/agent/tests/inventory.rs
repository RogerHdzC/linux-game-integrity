// SPDX-License-Identifier: Apache-2.0
use lgi_agent::{collect, Origin, ReadError, Source, MAX_READ, SECURE_BOOT};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::process::Command;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    fixture_kind: String,
    files: BTreeMap<String, String>,
    binary_files: BTreeMap<String, Vec<u8>>,
    directories: BTreeMap<String, Vec<String>>,
    nodes: Vec<String>,
    denied: Vec<String>,
}

impl Source for Fixture {
    fn origin(&self) -> Origin {
        Origin::Synthetic
    }
    fn read(&self, path: &str) -> Result<Vec<u8>, ReadError> {
        if self.denied.iter().any(|p| p == path) {
            return Err(ReadError::PermissionDenied);
        }
        self.binary_files
            .get(path)
            .cloned()
            .or_else(|| self.files.get(path).map(|s| s.as_bytes().to_vec()))
            .ok_or(ReadError::NotFound)
    }
    fn list(&self, path: &str) -> Result<Vec<String>, ReadError> {
        if self.denied.iter().any(|p| p == path) {
            return Err(ReadError::PermissionDenied);
        }
        self.directories
            .get(path)
            .cloned()
            .ok_or(ReadError::NotFound)
    }
    fn node(&self, path: &str) -> Result<bool, ReadError> {
        if self.denied.iter().any(|p| p == path) {
            return Err(ReadError::PermissionDenied);
        }
        if self.nodes.iter().any(|p| p == path) {
            Ok(true)
        } else {
            Err(ReadError::NotFound)
        }
    }
    fn probe_read(&self, path: &str) -> Result<bool, ReadError> {
        self.read(path).map(|_| true)
    }
}

fn fixture() -> Fixture {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../tests/fixtures/synthetic-linux.json")).unwrap();
    assert_eq!(fixture.fixture_kind, "synthetic");
    fixture
}

#[test]
fn synthetic_capabilities_never_become_verified_evidence() {
    let report = collect(&fixture());
    assert_eq!(report.platform.distribution.value.unwrap().id, "ubuntu");
    assert_eq!(report.platform.secure_boot.value, Some("enabled"));
    assert_eq!(report.platform.tpm.major_versions[0].value, Some(2));
    assert_eq!(
        report.platform.module_signature_enforcement.value,
        Some(true)
    );
    assert_eq!(report.platform.lockdown.value.as_deref(), Some("integrity"));
    assert_eq!(report.result, "INDETERMINATE");
    assert!(!report.evidence.cryptographically_backed);
    assert!(!report.evidence.server_verified);
    assert!(!report.evidence.measurements_collected);
    assert!(!report.evidence.quote_present);
}

#[test]
fn missing_interfaces_do_not_imply_disabled_security() {
    let report = collect(&Fixture::default());
    assert_eq!(report.platform.secure_boot.status, "unavailable");
    assert_eq!(report.platform.secure_boot.value, None);
    assert_eq!(report.platform.tpm.class_devices.value, None);
    assert_eq!(report.platform.environment_hint, "unknown");
    assert_eq!(report.result, "INDETERMINATE");
}

#[test]
fn denied_interfaces_preserve_error_and_other_observations() {
    let mut f = fixture();
    f.denied = vec![
        SECURE_BOOT.into(),
        "/etc/os-release".into(),
        "/sys/class/tpm".into(),
    ];
    f.files
        .insert("/usr/lib/os-release".into(), "ID=untrusted_fallback".into());
    let r = collect(&f);
    assert_eq!(
        r.platform.secure_boot.error,
        Some(ReadError::PermissionDenied)
    );
    assert_eq!(r.platform.distribution.source, "/etc/os-release");
    assert!(r.platform.distribution.value.is_none());
    assert_eq!(r.platform.tpm.class_devices.status, "error");
    assert!(r.platform.kernel_release.value.is_some());
}

#[test]
fn denied_ima_policy_does_not_hide_readable_logs_or_claim_coverage() {
    let mut f = fixture();
    f.denied.push("/sys/kernel/security/ima/policy".into());
    let r = collect(&f);
    let interfaces = &r.platform.measurement_interfaces;
    let policy = interfaces
        .iter()
        .find(|o| o.source.ends_with("/policy"))
        .unwrap();
    assert_eq!(policy.error, Some(ReadError::PermissionDenied));
    assert_eq!(policy.value, None);
    let log = interfaces
        .iter()
        .find(|o| o.source.ends_with("/ascii_runtime_measurements"))
        .unwrap();
    assert_eq!(log.value, Some(true));
    assert!(!r.evidence.measurements_collected);
    assert!(!r.evidence.cryptographically_backed);
    assert_eq!(r.result, "INDETERMINATE");
}

#[test]
fn missing_boot_log_and_malformed_tpm_version_remain_unknown() {
    let mut f = fixture();
    f.files
        .remove("/sys/kernel/security/tpm0/binary_bios_measurements");
    f.files.insert(
        "/sys/class/tpm/tpm0/tpm_version_major".into(),
        "unknown".into(),
    );
    let r = collect(&f);
    let log = r
        .platform
        .measurement_interfaces
        .iter()
        .find(|o| o.source.ends_with("/binary_bios_measurements"))
        .unwrap();
    assert_eq!(log.status, "unavailable");
    assert_eq!(log.value, None);
    assert_eq!(
        r.platform.tpm.major_versions[0].error,
        Some(ReadError::InvalidData)
    );
    assert_eq!(r.platform.tpm.command_access, "not-tested");
    assert_eq!(r.result, "INDETERMINATE");
}

#[test]
fn distro_falls_back_only_when_primary_file_is_missing() {
    let mut f = fixture();
    f.files.remove("/etc/os-release");
    f.files.insert(
        "/usr/lib/os-release".into(),
        "ID=fedora\nVERSION_ID=synthetic".into(),
    );
    let r = collect(&f);
    assert_eq!(r.platform.distribution.source, "/usr/lib/os-release");
    assert_eq!(r.platform.distribution.value.unwrap().id, "fedora");
}

#[test]
fn corrupt_or_oversized_reads_do_not_become_valid_observations() {
    let mut f = fixture();
    f.binary_files.insert("/etc/os-release".into(), vec![255]);
    f.files
        .insert("/proc/modules".into(), "x".repeat(MAX_READ + 1));
    f.files.insert(
        "/sys/module/module/parameters/sig_enforce".into(),
        "maybe".into(),
    );
    f.binary_files.insert(SECURE_BOOT.into(), vec![0]);
    let r = collect(&f);
    assert_eq!(r.platform.distribution.error, Some(ReadError::InvalidData));
    assert_eq!(r.platform.loaded_modules.error, Some(ReadError::TooLarge));
    assert_eq!(r.platform.module_signature_enforcement.value, None);
    assert_eq!(r.platform.secure_boot.error, Some(ReadError::InvalidData));
    assert_eq!(r.result, "INDETERMINATE");
}

#[test]
fn empty_modules_and_tpm_directory_are_observed_empty_lists() {
    let mut f = fixture();
    f.files.insert("/proc/modules".into(), String::new());
    f.directories.insert("/sys/class/tpm".into(), Vec::new());
    let r = collect(&f);
    assert!(r.platform.loaded_modules.value.unwrap().is_empty());
    assert_eq!(r.platform.tpm.class_devices.status, "observed");
    assert!(r.platform.tpm.class_devices.value.unwrap().is_empty());
}

#[test]
fn wsl_is_only_a_hint_and_other_kernels_do_not_prove_bare_metal() {
    let mut f = fixture();
    f.files.insert(
        "/proc/sys/kernel/osrelease".into(),
        "5.15-microsoft-standard-WSL2\n".into(),
    );
    assert_eq!(collect(&f).platform.environment_hint, "wsl");
    f.files.insert(
        "/proc/sys/kernel/osrelease".into(),
        "6.8-synthetic\n".into(),
    );
    assert_eq!(collect(&f).platform.environment_hint, "unknown");
}

#[test]
fn tpm_discovery_filters_names_and_handles_multiple_versions() {
    let mut f = fixture();
    f.directories.insert(
        "/sys/class/tpm".into(),
        vec!["tpm0".into(), "tpm2".into(), "tpm../../escape".into()],
    );
    f.files
        .insert("/sys/class/tpm/tpm2/tpm_version_major".into(), "1\n".into());
    let r = collect(&f);
    assert_eq!(r.platform.tpm.major_versions.len(), 2);
    assert_eq!(r.platform.tpm.major_versions[1].value, Some(1));
    assert_eq!(r.platform.tpm.command_access, "not-tested");
}

#[test]
fn cli_rejects_arguments_before_inventory() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgi-agent"))
        .arg("--root=/tmp")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn cli_live_output_is_json_and_never_accepts() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgi-agent"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["origin"], "live");
    assert_eq!(value["result"], "INDETERMINATE");
    assert_eq!(value["evidence"]["serverVerified"], false);
}
