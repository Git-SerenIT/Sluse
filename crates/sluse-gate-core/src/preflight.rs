// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The preflight checks and the posture list.
//!
//! Two lists with two different powers. **Gate**: a `Fail` and the box does not
//! start, no override. **Posture**: recorded and never blocking — the snapshot
//! is written once at core start and every audit record afterwards carries its
//! id, which is what makes "what was this machine like when that file was
//! admitted" answerable months later without repeating twenty fields on every
//! line.
//!
//! `user-not-local-admin` is on the posture list. That was jok's answer on
//! 2026-09-14 and it is the looser of the two readings: a developer running as
//! administrator is a fact worth recording about a run, not a reason to refuse
//! to start one. The docs are unchanged and it is not a decision yet
//! (`docs/sluse_prototype.md`, Provisional design points).
//!
//! ## Why this lives in Gate Core and not in `sluse-lifecycle`
//!
//! The plan put preflight in the lifecycle crate, and it could not stay there.
//! `/v1/health` reports the `posture_id` that every audit record cites, so the
//! core must have a snapshot before it answers its first request — and the
//! required check "gate reachable" *is* a call to `/v1/health`. Two implementations
//! would eventually disagree about the same machine, and the one that disagreed
//! would be the one in the audit trail. `sluse check` calls this module at M4
//! without starting a listener. jok's answer on 2026-09-16.
//!
//! ## What may not be done here
//!
//! **Local Win32 and registry calls only. No process spawns and no network.**
//! Never `dsregcmd`, `cmdkey`, `systeminfo` or any probe that leaves the
//! machine: those tripped SerenIT IT monitoring on 2026-09-14
//! (`docs/sluse_prototype.md`). Every check below is a syscall or a registry
//! read, and a check that cannot be answered that way reports
//! [`CheckOutcome::Unknown`] rather than reaching for a subprocess.
//!
//! ## What LOCAL cannot answer, and says so
//!
//! Three of the required checks are about a machine this prototype is not running on:
//! a hypervisor guest, a host-only network segment, an enforcing proxy. They
//! report [`CheckOutcome::NotApplicable`], which
//! passes the required checks. That is a deliberate looseness and the posture list beside it
//! is the reason it is tolerable: the things LOCAL cannot answer are written down
//! as unanswered rather than waved through as passes. **Nothing in a LOCAL
//! snapshot is evidence about the guest boundary** (D-010), and a result file
//! that quoted one as if it were would be wrong.

use std::path::Path;

use chrono::Utc;
use sluse_proto::{
    Check, CheckList, CheckOutcome, ContentHash, Environment, Loaded, PostureId, PostureSnapshot,
};

/// Run both lists and build the snapshot.
///
/// `certs_ok` is threaded in rather than checked here because Gate Core has
/// already had to load and parse its certificates to build a TLS config, and
/// re-reading them to answer a question already answered would let the two
/// answers differ.
pub fn run(loaded: &Loaded, certs: CertCheck) -> PostureSnapshot {
    let env = loaded.config.environment;
    let mut checks = Vec::new();

    // ---- Gate -------------------------------------------------------------
    //
    // `config-valid` cannot fail here by construction: nothing reaches this
    // function without a `Loaded`, and a config that did not load exits before
    // Gate Core starts. It is recorded as a pass anyway, because a snapshot
    // that silently omits a required check reads as a snapshot taken before the Gate
    // existed.
    checks.push(pass("config-valid").detail(format!(
        "schemaVersion {}, {} source(s)",
        sluse_proto::SCHEMA_VERSION,
        loaded.config.sources.len()
    )));

    checks.push(match &certs {
        CertCheck::Ok { pin } => pass("certs-present-and-pinned")
            .detail(format!("core leaf hashes to the configured pin {}", pin.short())),
        CertCheck::PinMismatch { expected, presented } => fail("certs-present-and-pinned").detail(
            format!("configured pin {} but the leaf hashes to {}", expected.short(), presented.short()),
        ),
        CertCheck::Missing { detail } => fail("certs-present-and-pinned").detail(detail.clone()),
    });

    checks.push(writable("artifacts-writable", &loaded.resolve(&loaded.config.artifacts)));

    // "gate reachable" is the required check Gate Core cannot run about itself:
    // it is a `GET /v1/health` from outside, and Gate Core is inside. `sluse
    // start` runs it at M4 and the snapshot in force by then already exists, so
    // it is recorded here as unanswered rather than as a pass this code did not
    // earn.
    checks.push(
        unknown("gate-reachable", CheckList::Required)
            .detail("answered by `sluse start` from outside the process".to_owned()),
    );

    // The guest checks the lifecycle service asked of Hyper-V for this open
    // (slice 5), handed over in `SLUSE_GUEST_CHECKS`. Gate Core cannot ask
    // them itself: it does not know which VM is the box. Absent, they stay
    // unanswered, as before.
    let guest: Option<serde_json::Value> =
        std::env::var("SLUSE_GUEST_CHECKS").ok().and_then(|v| serde_json::from_str(&v).ok());
    let answered = |key: &str, name: &str, list: CheckList| from_service(guest.as_ref(), key, name, list);

    for name in ["hypervisor-guest", "host-only-segment", "proxy-enforcing"] {
        let key = match name {
            "hypervisor-guest" => Some("hypervisorGuest"),
            "host-only-segment" => Some("hostOnlySegment"),
            _ => None,
        };
        if let Some(c) = key.and_then(|k| answered(k, name, CheckList::Required)) {
            checks.push(c);
            continue;
        }
        checks.push(match env {
            // Not a pass. This laptop is not a Hyper-V guest, has no host-only
            // segment and no enforcing proxy, and a `Pass` here would be a claim
            // about the boundary that a LOCAL run cannot make (D-010).
            Environment::Local => not_applicable(name)
                .detail("LOCAL: the prototype runs on the host, not in a guest".to_owned()),
            Environment::Demo => unknown("hypervisor-guest", CheckList::Required).rename(name).detail(
                match name {
                    "proxy-enforcing" => "DEMO: no check built; the proxy is Gate Front's",
                    _ => "DEMO: answered only by the service, for a box it opens",
                }
                .to_owned(),
            ),
        });
    }

    // ---- posture ----------------------------------------------------------
    // Nothing runs from Sluse Artifacts (D-039 slice 8): the admin deploys
    // the policy with Intune, so its absence is posture, never a refusal.
    checks.push(match env {
        Environment::Local => check("wdac-on-artifacts", CheckList::Posture, CheckOutcome::NotApplicable)
            .detail("LOCAL: no Sluse Artifacts of a user's to protect".to_owned()),
        Environment::Demo => platform::artifacts_policy(),
    });
    checks.push(platform::user_not_local_admin());
    checks.push(platform::hyperv_feature_present());
    checks.push(platform::hyperv_administrators_empty());
    checks.push(answered("enhancedSessionDisabled", "enhanced-session-disabled", CheckList::Posture).unwrap_or_else(|| {
        unknown("enhanced-session-disabled", CheckList::Posture).detail(
            match env {
                Environment::Local => "no host to ask in LOCAL",
                Environment::Demo => "answered by the service, for a box it opens",
            }
            .to_owned(),
        )
    }));
    checks.push(answered("guestServicesOff", "guest-services-off", CheckList::Posture).unwrap_or_else(|| {
        unknown("guest-services-off", CheckList::Posture).detail("answered by the service for a box it opens".to_owned())
    }));
    checks.push(platform::os_edition_and_build());
    checks.push(egress_catalog(loaded, shipped_catalog()));
    checks.push(match loaded.config.audit.sink {
        sluse_proto::AuditSinkKind::Eventlog => platform::audit_channel(),
        sluse_proto::AuditSinkKind::Jsonl => check("audit-channel", CheckList::Posture, CheckOutcome::NotApplicable)
            .detail("the audit sink is a file, not the Event Log".to_owned()),
    });

    PostureSnapshot {
        id: PostureId::mint(),
        ts: Utc::now(),
        box_id: loaded.config.box_id.clone(),
        config_version: loaded.version.clone(),
        environment: env,
        checks,
    }
}

/// One guest check as the service answered it: `true` passes, `false`
/// fails, and anything else, absent included, is not an answer.
fn from_service(guest: Option<&serde_json::Value>, key: &str, name: &str, list: CheckList) -> Option<Check> {
    let g = guest?;
    let pass = g.get(key)?.as_bool()?;
    let outcome = if pass { CheckOutcome::Pass } else { CheckOutcome::Fail };
    // The service's one `detail` is the segment's; every other check says
    // its own (L1, 2026-10-06: enhanced session failed with the segment's).
    let detail = match (key, pass) {
        ("hostOnlySegment", _) => g.get("detail").and_then(|d| d.as_str()).unwrap_or(""),
        ("hypervisorGuest", true) => "the box is a generation 2 Hyper-V VM",
        ("hypervisorGuest", false) => "the box is not a generation 2 Hyper-V VM",
        ("enhancedSessionDisabled", true) => "Hyper-V's enhanced session mode is off for this host",
        ("enhancedSessionDisabled", false) => "Hyper-V's enhanced session mode is on for this host",
        ("guestServicesOff", true) => "the box's Guest Service Interface is off",
        ("guestServicesOff", false) => "the box's Guest Service Interface is on",
        _ => "",
    };
    Some(check(name, list, outcome).detail(format!("asked of Hyper-V by the service: {detail}")))
}

/// What Gate Core found when it loaded its own certificate.
pub enum CertCheck {
    Ok { pin: ContentHash },
    PinMismatch { expected: ContentHash, presented: ContentHash },
    Missing { detail: String },
}

// ---------------------------------------------------------------------------
// Check builders
// ---------------------------------------------------------------------------

/// The Sluse Artifacts policy's id, as `packaging/intune/sluse-artifacts-deny.xml`
/// names it (a test keeps the two equal).
pub const ARTIFACTS_POLICY_ID: &str = "3CA83446-6F47-4A65-9891-2685B75CD7E3";

/// The bundle catalog this install ships (D-038 point 5): `version` in
/// `config\egress-catalog.json` beside the binaries' folder. `None` when
/// there is none, as in a build from the repository.
fn shipped_catalog() -> Option<u32> {
    let exe = std::env::current_exe().ok()?;
    let file = exe.parent()?.parent()?.join("config").join("egress-catalog.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(file).ok()?).ok()?;
    v["version"].as_u64().and_then(|n| u32::try_from(n).ok())
}

/// Whether the config was published against the catalog this install ships.
/// A newer one is a posture failure, which never blocks: **Sluse does not
/// widen a box's egress by itself** (D-038 point 5), so the admin is told and
/// republishes. ponytail: in the posture snapshot only; the Event Log gets it
/// with the dedicated channel (D-039 slice 7).
fn egress_catalog(loaded: &Loaded, shipped: Option<u32>) -> Check {
    const NAME: &str = "egress-catalog";
    let config = loaded.config.egress.as_ref().and_then(|e| e.catalog);
    match (config, shipped) {
        (_, None) => check(NAME, CheckList::Posture, CheckOutcome::NotApplicable)
            .detail("this install ships no bundle catalog".to_owned()),
        (None, Some(s)) => check(NAME, CheckList::Posture, CheckOutcome::NotApplicable)
            .detail(format!("the config names no catalog; this install ships version {s}")),
        (Some(c), Some(s)) if c >= s => check(NAME, CheckList::Posture, CheckOutcome::Pass)
            .detail(format!("the config's catalog is version {c}; this install ships {s}")),
        (Some(c), Some(s)) => check(NAME, CheckList::Posture, CheckOutcome::Fail).detail(format!(
            "this install ships catalog version {s}, newer than the config's {c}. Sluse does not widen \
             the box's egress by itself: publish the configuration again from Sluse Admin to take it"
        )),
    }
}

fn check(name: &str, list: CheckList, outcome: CheckOutcome) -> Check {
    Check { name: name.to_owned(), list, outcome, detail: None }
}

fn pass(name: &str) -> Check {
    check(name, CheckList::Required, CheckOutcome::Pass)
}

fn fail(name: &str) -> Check {
    check(name, CheckList::Required, CheckOutcome::Fail)
}

fn not_applicable(name: &str) -> Check {
    check(name, CheckList::Required, CheckOutcome::NotApplicable)
}

fn unknown(name: &str, list: CheckList) -> Check {
    check(name, list, CheckOutcome::Unknown)
}

trait WithDetail {
    fn detail(self, d: String) -> Check;
    fn rename(self, name: &str) -> Check;
}

impl WithDetail for Check {
    fn detail(mut self, d: String) -> Check {
        self.detail = Some(d);
        self
    }
    fn rename(mut self, name: &str) -> Check {
        self.name = name.to_owned();
        self
    }
}

/// Can Gate Core create and remove a file where artifacts will land?
///
/// A probe file, created and removed. Checking the ACL instead would answer a
/// different and less useful question — whether the permissions look right —
/// and the publish route needs the one this answers.
fn writable(name: &str, dir: &Path) -> Check {
    // As the user who will publish here, on a device (D-031).
    let _as_user = match crate::as_user::enter() {
        Ok(g) => g,
        Err(e) => return fail(name).detail(e.to_string()),
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        return fail(name).detail(format!("{} cannot be created: {e}", dir.display()));
    }
    let probe = dir.join(format!(".sluse-probe-{}", std::process::id()));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            pass(name).detail(dir.display().to_string())
        }
        Err(e) => fail(name).detail(format!("{} is not writable: {e}", dir.display())),
    }
}

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::*;
    use windows::core::PCWSTR;
    use windows::core::BOOL;
    use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, CreateWellKnownSid, EqualSid, FreeSid,
        GetTokenInformation, LookupAccountSidW, TokenGroups, WinBuiltinAdministratorsSid,
        WinBuiltinHyperVAdminsSid, PSID, SECURITY_MAX_SID_SIZE, SECURITY_NT_AUTHORITY, SID_NAME_USE,
        TOKEN_GROUPS, WELL_KNOWN_SID_TYPE,
    };
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetLocalGroupGetMembers, LOCALGROUP_MEMBERS_INFO_3, MAX_PREFERRED_LENGTH,
    };
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
    };

    const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x20;
    const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x220;

    /// Is the process's token a member of the local Administrators group?
    ///
    /// `CheckTokenMembership` with a `NULL` token asks about the *effective*
    /// token of the calling thread, which is the question worth asking: an
    /// elevated process and a non-elevated one owned by the same person give
    /// different answers, and the one that matters is the one this core is
    /// actually running with.
    ///
    /// Posture, not Gate. Recorded on every audit record via the snapshot id and
    /// never a reason to refuse to start (jok, 2026-09-14).
    pub(super) fn user_not_local_admin() -> Check {
        // On a device Gate Core is SYSTEM, and its own token answered "yes"
        // every time (L1, 2026-10-01). The question is about the box's user,
        // whose token the service handed over (D-031).
        if let Some(token) = crate::as_user::token() {
            return box_user_not_admin(HANDLE(token as *mut core::ffi::c_void));
        }
        let mut sid = PSID::default();
        let ok = unsafe {
            AllocateAndInitializeSid(
                &SECURITY_NT_AUTHORITY,
                2,
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };
        if ok.is_err() || sid.is_invalid() {
            return unknown("user-not-local-admin", CheckList::Posture)
                .detail("could not build the Administrators SID".to_owned());
        }

        let mut member = BOOL::default();
        let result = unsafe { CheckTokenMembership(Some(HANDLE::default()), sid, &mut member) };
        unsafe { FreeSid(sid) };

        match result {
            Err(e) => unknown("user-not-local-admin", CheckList::Posture)
                .detail(format!("CheckTokenMembership failed: {e}")),
            Ok(()) if member.as_bool() => check(
                "user-not-local-admin",
                CheckList::Posture,
                CheckOutcome::Fail,
            )
            .detail("this process is running as a local administrator".to_owned()),
            Ok(()) => check("user-not-local-admin", CheckList::Posture, CheckOutcome::Pass),
        }
    }

    /// Is the Hyper-V VMMS service registered?
    ///
    /// A registry read, not a service query: present in the registry says the
    /// feature is installed, which is the posture fact worth recording, and it
    /// costs no handle to the service control manager.
    /// Is the Sluse Artifacts policy deployed (D-039 slice 8)? Its `.cip` in
    /// CodeIntegrity's active folder, under the GUID in
    /// `packaging/intune/sluse-artifacts-deny.xml`.
    /// ponytail: deployed, not proven enforced; `CiTool --list-policies`
    /// (Windows 11 22H2+) says enforced, if the test run shows it matters.
    pub(super) fn artifacts_policy() -> Check {
        let name = "wdac-on-artifacts";
        let windir = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let cip = std::path::Path::new(&windir)
            .join("System32\\CodeIntegrity\\CiPolicies\\Active")
            .join(format!("{{{}}}.cip", super::ARTIFACTS_POLICY_ID));
        if cip.is_file() {
            check(name, CheckList::Posture, CheckOutcome::Pass)
                .detail("the Sluse Artifacts policy is deployed".to_owned())
        } else {
            check(name, CheckList::Posture, CheckOutcome::Fail).detail(
                "the Sluse Artifacts policy is not deployed: a file the box publishes can be run from there. \
                 Deploy sluse-artifacts-deny with Intune (GUIDE.md, \"Blocking programs in Sluse Artifacts\")"
                    .to_owned(),
            )
        }
    }

    /// Is the Sluse log there, with the descriptor that admits SYSTEM's
    /// writes only (D-023)? Posture: an older device writes to the
    /// Application log, which any process can write to, and that is worth
    /// a line, not a refusal.
    pub(super) fn audit_channel() -> Check {
        let name = "audit-channel";
        match reg_value("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Sluse", "CustomSD") {
            Some(sd) if sd == crate::audit::AUDIT_SDDL => check(name, CheckList::Posture, CheckOutcome::Pass)
                .detail("the Sluse log admits SYSTEM's writes only".to_owned()),
            Some(sd) => check(name, CheckList::Posture, CheckOutcome::Fail).detail(format!("the Sluse log's CustomSD is {sd}")),
            None => check(name, CheckList::Posture, CheckOutcome::Fail).detail(
                "there is no Sluse log: records go to the Application log, which any process can write to".to_owned(),
            ),
        }
    }

    pub(super) fn hyperv_feature_present() -> Check {
        let name = "hyperv-feature-present";
        match reg_value("SYSTEM\\CurrentControlSet\\Services\\vmms", "ImagePath") {
            Some(_) => check(name, CheckList::Posture, CheckOutcome::Pass)
                .detail("vmms is registered".to_owned()),
            // Absent is a fact, not a failure: this is posture, and a laptop
            // without Hyper-V installed is a laptop without Hyper-V installed.
            None => check(name, CheckList::Posture, CheckOutcome::Fail)
                .detail("vmms is not registered; Hyper-V is not installed".to_owned()),
        }
    }

    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Option<[u8; SECURITY_MAX_SID_SIZE as usize]> {
        let mut buf = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = buf.len() as u32;
        unsafe { CreateWellKnownSid(kind, None, Some(PSID(buf.as_mut_ptr().cast())), &mut size) }.ok()?;
        Some(buf)
    }

    /// Whether the box's user holds Administrators in their token at all,
    /// **deny-only included**: a UAC-filtered administrator is still one, a
    /// prompt away from elevating. A group scan, not `CheckTokenMembership`,
    /// which wants an impersonation token and ignores deny-only entries.
    fn box_user_not_admin(token: HANDLE) -> Check {
        let name = "user-not-local-admin";
        let Some(mut admins) = well_known(WinBuiltinAdministratorsSid) else {
            return unknown(name, CheckList::Posture).detail("could not build the Administrators SID".to_owned());
        };
        let mut len = 0u32;
        let _ = unsafe { GetTokenInformation(token, TokenGroups, None, 0, &mut len) };
        // u64s, so the buffer is aligned for the SID pointers inside it.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        if let Err(e) = unsafe { GetTokenInformation(token, TokenGroups, Some(buf.as_mut_ptr().cast()), len, &mut len) } {
            return unknown(name, CheckList::Posture).detail(format!("the box user's groups: {e}"));
        }
        let groups = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
        let all = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
        let admins = PSID(admins.as_mut_ptr().cast());
        match all.iter().find(|g| unsafe { EqualSid(g.Sid, admins) }.is_ok()) {
            // SE_GROUP_USE_FOR_DENY_ONLY
            Some(g) if g.Attributes & 0x10 != 0 => check(name, CheckList::Posture, CheckOutcome::Fail)
                .detail("the box's user is a local administrator, UAC-filtered".to_owned()),
            Some(_) => check(name, CheckList::Posture, CheckOutcome::Fail)
                .detail("the box's user is a local administrator, elevated".to_owned()),
            None => check(name, CheckList::Posture, CheckOutcome::Pass)
                .detail("the box's user is not a local administrator".to_owned()),
        }
    }

    /// Is the Hyper-V Administrators group empty?
    ///
    /// Its members configure every VM's disks and network, and read every
    /// box's serial log (D-030): local-admin-equivalent for the box. The
    /// group is found by its well-known SID and its name looked up, because
    /// the name is localised.
    pub(super) fn hyperv_administrators_empty() -> Check {
        let name = "hyperv-administrators-empty";
        let Some(mut sid) = well_known(WinBuiltinHyperVAdminsSid) else {
            return unknown(name, CheckList::Posture).detail("could not build the Hyper-V Administrators SID".to_owned());
        };
        let (mut group, mut domain) = ([0u16; 256], [0u16; 256]);
        let (mut glen, mut dlen) = (group.len() as u32, domain.len() as u32);
        let mut kind = SID_NAME_USE::default();
        let looked_up = unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                PSID(sid.as_mut_ptr().cast()),
                Some(windows::core::PWSTR(group.as_mut_ptr())),
                &mut glen,
                Some(windows::core::PWSTR(domain.as_mut_ptr())),
                &mut dlen,
                &mut kind,
            )
        };
        if let Err(e) = looked_up {
            // No Hyper-V, no group: nothing to be a member of.
            return check(name, CheckList::Posture, CheckOutcome::Pass)
                .detail(format!("the group does not exist here: {e}"));
        }
        let mut members: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        let status = unsafe {
            NetLocalGroupGetMembers(
                PCWSTR::null(),
                PCWSTR(group.as_ptr()),
                3,
                &mut members,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                None,
            )
        };
        if status != 0 {
            return unknown(name, CheckList::Posture).detail(format!("NetLocalGroupGetMembers returned {status}"));
        }
        // An empty group comes back as a null buffer, and `from_raw_parts`
        // on null is undefined even at length zero (CI, 2026-10-01).
        let names: Vec<String> = if members.is_null() || read == 0 {
            Vec::new()
        } else {
            unsafe {
                std::slice::from_raw_parts(members as *const LOCALGROUP_MEMBERS_INFO_3, read as usize)
                    .iter()
                    .map(|m| m.lgrmi3_domainandname.to_string().unwrap_or_default())
                    .collect()
            }
        };
        unsafe { NetApiBufferFree(Some(members as *const core::ffi::c_void)) };
        if total == 0 {
            check(name, CheckList::Posture, CheckOutcome::Pass).detail("the group is empty".to_owned())
        } else {
            check(name, CheckList::Posture, CheckOutcome::Fail)
                .detail(format!("{total} member(s): {}", names.join(", ")))
        }
    }

    pub(super) fn os_edition_and_build() -> Check {
        let key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        let edition = reg_value(key, "EditionID");
        let build = reg_value(key, "CurrentBuild");
        let display = reg_value(key, "DisplayVersion");
        match (edition, build) {
            (Some(e), Some(b)) => {
                let extra = display.map(|d| format!(" {d}")).unwrap_or_default();
                // A value, not a verdict. There is no edition this prototype
                // requires, so `Pass` here means "recorded", and the detail is
                // the part anyone will read.
                check("os-edition-and-build", CheckList::Posture, CheckOutcome::Pass)
                    .detail(format!("{e}{extra} build {b}"))
            }
            _ => unknown("os-edition-and-build", CheckList::Posture)
                .detail("CurrentVersion did not answer".to_owned()),
        }
    }

    /// One `HKLM` string value, or `None`.
    fn reg_value(subkey: &str, value: &str) -> Option<String> {
        let subkey = wide(subkey);
        let value = wide(value);
        let mut len: u32 = 0;

        // Two calls: the first sizes the buffer, the second fills it. Asking for
        // `RRF_RT_REG_SZ` means a value of another type is a miss rather than
        // bytes reinterpreted as text.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                None,
                Some(&mut len),
            )
        };
        if rc != ERROR_SUCCESS || len == 0 {
            return None;
        }

        let mut buf = vec![0u16; (len as usize).div_ceil(2)];
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buf.as_mut_ptr().cast()),
                Some(&mut len),
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }

        let chars = (len as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..chars]);
        let s = s.trim_end_matches('\0').to_owned();
        (!s.is_empty()).then_some(s)
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    // Sluse is a Windows product. This exists so the crate builds on a developer's
    // other machine and so `cargo check` in CI on Linux is meaningful; every check
    // reports `Unknown`, which is exactly what it knows.
    macro_rules! unanswerable {
        ($fn_name:ident, $check:literal) => {
            pub(super) fn $fn_name() -> Check {
                unknown($check, CheckList::Posture)
                    .detail("not a Windows host".to_owned())
            }
        };
    }

    unanswerable!(user_not_local_admin, "user-not-local-admin");
    unanswerable!(hyperv_feature_present, "hyperv-feature-present");
    unanswerable!(audit_channel, "audit-channel");
    unanswerable!(artifacts_policy, "wdac-on-artifacts");
    unanswerable!(hyperv_administrators_empty, "hyperv-administrators-empty");
    unanswerable!(os_edition_and_build, "os-edition-and-build");
}

/// Print a snapshot as two lists.
///
/// Here rather than in either binary because `sluse-gate-core --check` and `sluse
/// check` must describe one machine the same way. Two printers would eventually
/// disagree about what `unknown` looks like, and the required-versus-posture
/// distinction is exactly the thing a reader is meant to take from the shape of
/// the output.
pub fn print(posture: &PostureSnapshot) {
    for list in [CheckList::Required, CheckList::Posture] {
        let label = match list {
            CheckList::Required => "required",
            CheckList::Posture => "posture",
        };
        println!("{label}");
        for c in posture.checks.iter().filter(|c| c.list == list) {
            let mark = match c.outcome {
                CheckOutcome::Pass => "pass",
                CheckOutcome::Fail => "FAIL",
                CheckOutcome::NotApplicable => "n/a ",
                // Distinct from a failure on purpose: an unknown reported as a
                // pass is a claim nobody made, and as a failure it stops a box
                // for no reason.
                CheckOutcome::Unknown => "?   ",
            };
            match &c.detail {
                Some(d) => println!("  {mark}  {:<28} {d}", c.name),
                None => println!("  {mark}  {}", c.name),
            }
        }
    }
    if !posture.required_passed() {
        println!();
        println!("A required check failed. Serving will refuse to start; posture never blocks.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(dir: &Path) -> Loaded {
        let authored = format!(
            r#"{{
              "schemaVersion": 3,
              "sources": [{{
                "name": "fixture",
                "kind": {{ "type": "local-folder", "address": {{ "root": {root} }} }},
                "scope": [],
                "sensitivity": 1
              }}],
              "volume": {{ "admissions": 25, "windowSeconds": 60 }}
            }}"#,
            root = serde_json::to_string(dir).unwrap(),
        );
        let device = format!(
            r#"{{
              "boxId": "box-local-test",
              "environment": "local",
              "gate": {{
                "listen": "127.0.0.1:7580", "url": "https://127.0.0.1:7580",
                "certPath": "certs/core.pem", "keyPath": "certs/core.key",
                "clientCaPath": "certs/client-ca.pem",
                "certPin": "{zero}"
              }},
              "endpoint": {{
                "clientCertPath": "certs/endpoint.pem",
                "clientKeyPath": "certs/endpoint.key",
                "consoleListen": "127.0.0.1:7582"
              }},
              "artifacts": "artifacts",
              "workspace": "workspace",
              "journalDir": "journal",
              "audit": {{ "sink": "jsonl", "path": "audit/core.jsonl" }}
            }}"#,
            zero = "0".repeat(64),
        );
        sluse_proto::config::load_from_bytes(authored.as_bytes(), device.as_bytes(), &dir.join("local.json")).unwrap()
    }

    fn ok_certs() -> CertCheck {
        CertCheck::Ok { pin: ContentHash::of(b"a leaf") }
    }

    fn named<'a>(snap: &'a PostureSnapshot, name: &str) -> &'a Check {
        snap.checks.iter().find(|c| c.name == name).expect(name)
    }

    #[test]
    fn a_local_snapshot_passes_the_gate_and_says_what_it_could_not_answer() {
        let dir = tempfile::tempdir().unwrap();
        let snap = run(&loaded(dir.path()), ok_certs());

        assert!(snap.required_passed());
        assert_eq!(snap.environment, Environment::Local);
        assert_eq!(snap.box_id.as_str(), "box-local-test");

        // The four the prototype is not in a position to answer are
        // `NotApplicable`, never `Pass`. A pass here would be a claim about the
        // guest boundary that a LOCAL run cannot make.
        for name in ["hypervisor-guest", "host-only-segment", "proxy-enforcing"] {
            let c = named(&snap, name);
            assert_eq!(c.outcome, CheckOutcome::NotApplicable, "{name}");
            assert_eq!(c.list, CheckList::Required);
        }
        // The admin's to deploy (D-039 slice 8): posture, never required.
        let w = named(&snap, "wdac-on-artifacts");
        assert_eq!((w.outcome, w.list), (CheckOutcome::NotApplicable, CheckList::Posture));
        assert!(include_str!("../../../packaging/intune/sluse-artifacts-deny.xml").contains(ARTIFACTS_POLICY_ID));

        // And the one Gate Core cannot run about itself is unanswered, not
        // assumed.
        assert_eq!(named(&snap, "gate-reachable").outcome, CheckOutcome::Unknown);
    }

    #[test]
    fn a_pin_mismatch_fails_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let snap = run(
            &loaded(dir.path()),
            CertCheck::PinMismatch {
                expected: ContentHash::of(b"configured"),
                presented: ContentHash::of(b"actual"),
            },
        );
        assert!(!snap.required_passed());
        let c = named(&snap, "certs-present-and-pinned");
        assert_eq!(c.outcome, CheckOutcome::Fail);
        // Both hashes in the detail: a person comparing them by eye is the
        // point, and one alone would not tell them which end to fix.
        assert!(c.detail.as_ref().unwrap().contains("configured pin"));
    }

    #[test]
    fn a_missing_certificate_fails_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let snap = run(
            &loaded(dir.path()),
            CertCheck::Missing { detail: "certs\\core.pem does not exist".to_owned() },
        );
        assert!(!snap.required_passed());
    }

    #[test]
    fn a_newer_shipped_catalog_is_a_posture_failure_and_never_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = loaded(dir.path());
        assert_eq!(egress_catalog(&l, None).outcome, CheckOutcome::NotApplicable);
        l.config.egress = Some(sluse_proto::EgressConfig { catalog: Some(1), ..Default::default() });
        assert_eq!(egress_catalog(&l, Some(1)).outcome, CheckOutcome::Pass);
        let newer = egress_catalog(&l, Some(2));
        assert_eq!((newer.outcome, newer.list), (CheckOutcome::Fail, CheckList::Posture));
        assert!(newer.detail.unwrap().contains("Sluse Admin"));
    }

    #[test]
    fn posture_never_blocks_however_it_comes_out() {
        let dir = tempfile::tempdir().unwrap();
        let snap = run(&loaded(dir.path()), ok_certs());

        // Whatever this machine is, the required checks ignore the posture list entirely.
        // The checks below may pass or fail depending on whose laptop this is;
        // what is under test is that it does not matter to the required checks.
        let posture: Vec<_> = snap.checks.iter().filter(|c| c.list == CheckList::Posture).collect();
        assert_eq!(posture.len(), 9, "nine posture checks, whatever they answer");
        assert!(snap.required_passed());
    }

    #[test]
    fn the_services_guest_answers_pass_fail_or_say_nothing() {
        let g = serde_json::json!({ "hostOnlySegment": false, "hypervisorGuest": true, "odd": "yes", "detail": "switch X" });
        let c = from_service(Some(&g), "hostOnlySegment", "host-only-segment", CheckList::Required).unwrap();
        assert_eq!(c.outcome, CheckOutcome::Fail, "a box on the wrong switch fails a required check");
        assert!(c.detail.unwrap().contains("switch X"));
        let c = from_service(Some(&g), "hypervisorGuest", "hypervisor-guest", CheckList::Required).unwrap();
        assert_eq!(c.outcome, CheckOutcome::Pass);
        assert!(!c.detail.unwrap().contains("switch X"), "the segment's detail is the segment's alone");
        let g = serde_json::json!({ "enhancedSessionDisabled": false, "detail": "switch X" });
        let c = from_service(Some(&g), "enhancedSessionDisabled", "enhanced-session-disabled", CheckList::Posture).unwrap();
        assert!(c.detail.unwrap().contains("enhanced session mode is on"), "L1, 2026-10-06");
        assert!(from_service(Some(&g), "odd", "x", CheckList::Required).is_none(), "not a bool is not an answer");
        assert!(from_service(Some(&g), "missing", "x", CheckList::Required).is_none());
        assert!(from_service(None, "hostOnlySegment", "x", CheckList::Required).is_none());
    }

    #[test]
    fn artifacts_writable_is_answered_by_writing_not_by_reading_an_acl() {
        let dir = tempfile::tempdir().unwrap();
        let snap = run(&loaded(dir.path()), ok_certs());
        let c = named(&snap, "artifacts-writable");
        assert_eq!(c.outcome, CheckOutcome::Pass);
        // The directory was created by the check, and the probe file it wrote is
        // gone again.
        let artifacts = dir.path().join("artifacts");
        assert!(artifacts.is_dir());
        assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 0);
    }

    #[test]
    fn every_check_has_a_name_and_no_name_appears_twice() {
        let dir = tempfile::tempdir().unwrap();
        let snap = run(&loaded(dir.path()), ok_certs());
        let mut names: Vec<&str> = snap.checks.iter().map(|c| c.name.as_str()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        // A duplicate name would make the snapshot ambiguous to anything reading
        // it back by name, which is how the console reads it (M5).
        assert_eq!(names.len(), before, "duplicate check name in the snapshot");
        assert!(snap.checks.iter().all(|c| !c.name.is_empty()));
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_checks_answer_rather_than_panicking() {
        // The values depend on the machine; what is under test is that the
        // Win32 and registry calls are well formed and return something.
        let edition = platform::os_edition_and_build();
        assert_ne!(
            edition.outcome,
            CheckOutcome::Unknown,
            "CurrentVersion should answer on a real Windows host: {:?}",
            edition.detail
        );
        assert!(edition.detail.unwrap().contains("build"));

        let admin = platform::user_not_local_admin();
        assert_ne!(admin.outcome, CheckOutcome::Unknown, "CheckTokenMembership should answer");
        assert_eq!(admin.list, CheckList::Posture);
    }
}
