// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from Chaperone crates/chapr-endpoint/src/identity.rs:24-50
// (`principal_from_parts` and its accountability-grade note). D-003 allows
// reuse, not vendoring.

//! Who the broker is acting as.
//!
//! Invariant 8 — *box authority never exceeds the user's own* — is structural:
//! the broker acts as the user, so it can reach exactly what they can reach and
//! nothing else. How it comes to act as them is the part that differs by
//! environment, and the audit record has to say which:
//!
//! - **LOCAL.** The broker runs in jok's own session as jok. The identity is the
//!   OS logon, taken from the environment, and it is recorded as
//!   [`UserKind::OsProcess`]. Invariant 8 holds here because the process *is*
//!   the user — there is no impersonation, no token, and nothing to verify.
//! - **DEMO and the product.** The broker runs as SYSTEM and impersonates the
//!   signed-in user for SMB, or calls SharePoint with the user's own delegated
//!   token, redeemed as a public client from the host shell's sign-in (D-036).
//!   The identity is an Entra UPN and is recorded as [`UserKind::Entra`].
//!
//! ## Why the record carries the kind and not just a name
//!
//! A name alone would let a LOCAL result be read as evidence about identity, and
//! it is not: **an OS-process identity is accountability-grade, not
//! evidence-grade**. It is read from the process environment, and anything that
//! can start the broker can set it. That is fine for what LOCAL proves —
//! functionality, UI, NTFS semantics — and worthless as a claim about who
//! admitted a file, which is why `CLAUDE.md` forbids a LOCAL result from
//! claiming anything about identity.
//!
//! The verified path is M7's `sharepoint` source kind: S-3 ran it for one user
//! in one tenant, and SMB as the user is not proven. Where it is not, the
//! authenticated-user claim in `docs/audit.md` is design intent, and
//! [`UserKind`] is how the record admits that rather than writing a name and
//! hoping.

use sluse_proto::{Environment, UserRef};

/// The identity to stamp on this broker's records.
///
/// `Local` reads the OS logon; `Demo` has no verified identity to read until
/// M7 wires the token, and says so rather than inventing one.
pub fn acting_as(environment: Environment) -> UserRef {
    match environment {
        Environment::Local => UserRef::os_process(os_logon()),
        // Deliberately the same value, deliberately still `OsProcess`: the
        // broker in DEMO is not yet impersonating anyone, and a record that said
        // `entra` before M7 would be the one lie this design cannot afford.
        Environment::Demo => UserRef::os_process(os_logon()),
    }
}

/// `DOMAIN\user` from the process environment.
fn os_logon() -> String {
    let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    from_parts(get("USERDOMAIN"), get("USERNAME"), get("USER").or_else(|| get("LOGNAME")))
}

/// The derivation, without touching the environment, so it can be tested.
fn from_parts(domain: Option<String>, user: Option<String>, unix: Option<String>) -> String {
    match (domain, user, unix) {
        (Some(d), Some(u), _) => format!("{d}\\{u}"),
        (None, Some(u), _) => u,
        (_, None, Some(u)) => u,
        // Not a fallback that pretends: a record with this in it is a record
        // nobody should treat as naming a person.
        _ => "UNKNOWN\\user".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluse_proto::UserKind;

    #[test]
    fn windows_logon_is_domain_qualified() {
        assert_eq!(
            from_parts(Some("SERENIT".into()), Some("jok".into()), None),
            "SERENIT\\jok"
        );
    }

    #[test]
    fn a_bare_username_survives_a_missing_domain() {
        assert_eq!(from_parts(None, Some("jok".into()), None), "jok");
    }

    #[test]
    fn nothing_known_is_visibly_nothing_known() {
        assert_eq!(from_parts(None, None, None), "UNKNOWN\\user");
    }

    #[test]
    fn local_is_recorded_as_an_os_process_identity() {
        // The one assertion that matters: a LOCAL record must never be readable
        // as evidence about an authenticated user.
        assert_eq!(acting_as(Environment::Local).kind, UserKind::OsProcess);
        assert_eq!(acting_as(Environment::Demo).kind, UserKind::OsProcess);
    }
}

/// Why the Windows user `sid` is not shown to be the Entra user `who`, or
/// `None` when it is (D-057). An Entra account's SID on an Entra-joined
/// device is `S-1-12-1-` and the four words of its object id; a domain
/// account's is its AD SID, which Entra carries as `onprem_sid` for a synced
/// user. Nothing else is taken as a match: a name can be the same for two
/// people, a SID cannot.
pub fn windows_mismatch(sid: &str, who: &crate::entra::Identity) -> Option<String> {
    let matched = match entra_object_id(sid) {
        Some(oid) => oid.eq_ignore_ascii_case(&who.oid),
        None => who.onprem_sid.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(sid)),
    };
    (!matched).then(|| {
        format!(
            "Windows is signed in as {sid}, and Sluse as {}{}. Files on this device are read and written as \
             the Windows user, so Sluse does not touch them while the two are not the same person. Sign in to \
             Sluse with the account you use for Windows; if you did, send the details to your IT department",
            who.upn,
            if sid.starts_with("S-1-12-1-") || who.onprem_sid.is_some() { "" } else { " (the sign-in carries no on-premises SID to compare)" },
        )
    })
}

/// The object id an Entra account's Windows SID encodes: `S-1-12-1-a-b-c-d`,
/// the GUID's sixteen bytes as four little-endian words.
fn entra_object_id(sid: &str) -> Option<String> {
    let words: Vec<u32> = sid.strip_prefix("S-1-12-1-")?.split('-').map(|w| w.parse().ok()).collect::<Option<_>>()?;
    let [a, b, c, d] = words[..] else { return None };
    let mut bytes = [0u8; 16];
    for (i, w) in [a, b, c, d].into_iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let h = |r: std::ops::Range<usize>, rev: bool| {
        let mut part = bytes[r].to_vec();
        if rev {
            part.reverse();
        }
        part.iter().map(|x| format!("{x:02x}")).collect::<String>()
    };
    Some(format!("{}-{}-{}-{}-{}", h(0..4, true), h(4..6, true), h(6..8, true), h(8..10, false), h(10..16, false)))
}

#[cfg(test)]
mod windows_tests {
    use super::*;
    use crate::entra::Identity;

    fn who(oid: &str, onprem_sid: Option<&str>) -> Identity {
        Identity { oid: oid.into(), upn: "fjeder@example.org".into(), tid: "t".into(), onprem_sid: onprem_sid.map(Into::into) }
    }

    #[test]
    fn an_entra_accounts_sid_is_its_object_id() {
        // The published example of the mapping, and a test account's.
        assert_eq!(
            entra_object_id("S-1-12-1-1943430372-1249052806-2496021943-3034400218").as_deref(),
            Some("73d664e4-0886-4a73-b745-c694da45ddb4")
        );
        let adele = "6a33018f-cc3b-44c5-bf70-24c219f2c936";
        assert_eq!(windows_mismatch("S-1-12-1-1781727631-1153813563-3257168063-919204377", &who(adele, None)), None);
        assert!(windows_mismatch("S-1-12-1-1943430372-1249052806-2496021943-3034400218", &who(adele, None)).is_some());
        assert_eq!(entra_object_id("S-1-12-1-1-2-3"), None);
    }

    #[test]
    fn a_domain_account_matches_only_its_onprem_sid() {
        let sid = "S-1-5-21-1004336348-1177238915-682003330-1104";
        assert_eq!(windows_mismatch(sid, &who("x", Some(sid))), None);
        assert!(windows_mismatch(sid, &who("x", Some("S-1-5-21-1-2-3-500"))).is_some());
        let none = windows_mismatch(sid, &who("x", None)).unwrap();
        assert!(none.contains("no on-premises SID"), "{none}");
    }
}
