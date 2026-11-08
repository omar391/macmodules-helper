//! One-use package-specific rights, acquired by the requesting user process.
//! The daemon imports external authorization and checks existing rights only.
//! It never extends an imported authorization using its root identity.
use super::{Identity, InstallerApprovalQuery};
use anyhow::{bail, Context, Result};
use objc2_core_foundation::{
    kCFBooleanFalse, kCFBooleanTrue, CFDictionary, CFNumber, CFString, CFType,
};
use objc2_security::{
    AuthorizationCopyRights, AuthorizationCreate, AuthorizationCreateFromExternalForm,
    AuthorizationExternalForm, AuthorizationFlags, AuthorizationFree, AuthorizationItem,
    AuthorizationItemSet, AuthorizationRef, AuthorizationRightRemove, AuthorizationRightSet,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::Read;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovedRequest {
    pub approval: InstallerApprovalQuery,
    pub challenge: String,
    pub authorization: Vec<i8>,
}

struct Pending {
    identity: Identity,
    publisher: String,
    package: String,
    revoke: bool,
    expires: Instant,
}
static PENDING: OnceLock<Mutex<BTreeMap<String, Pending>>> = OnceLock::new();
fn pending() -> &'static Mutex<BTreeMap<String, Pending>> {
    PENDING.get_or_init(Mutex::default)
}

struct Authorization(AuthorizationRef);
impl Authorization {
    fn empty() -> Result<Self> {
        let mut reference: AuthorizationRef = std::ptr::null();
        let status = unsafe {
            AuthorizationCreate(
                std::ptr::null(),
                std::ptr::null(),
                AuthorizationFlags::Defaults,
                &mut reference,
            )
        };
        if status != 0 || reference.is_null() {
            bail!("authorization reference unavailable ({status})");
        }
        Ok(Self(reference))
    }
}
impl Drop for Authorization {
    fn drop(&mut self) {
        unsafe {
            AuthorizationFree(self.0, AuthorizationFlags::DestroyRights);
        }
    }
}
fn right_pointer(name: &CString) -> NonNull<std::ffi::c_char> {
    // CString always has an allocated NUL-terminated buffer.
    unsafe { NonNull::new_unchecked(name.as_ptr().cast_mut()) }
}
fn remove_right(name: &str) {
    if let (Ok(auth), Ok(name)) = (Authorization::empty(), CString::new(name)) {
        unsafe {
            AuthorizationRightRemove(auth.0, right_pointer(&name));
        }
    }
}

pub(super) fn prepare(
    identity: &Identity,
    query: &InstallerApprovalQuery,
    revoke: bool,
) -> Result<String> {
    super::validate_team_identifier(&query.publisher_team_identifier)?;
    super::validate_package_identifier(&query.package_identifier)?;
    let mut entries = pending()
        .lock()
        .map_err(|_| anyhow::anyhow!("package authorization state unavailable"))?;
    entries.retain(|name, entry| {
        if Instant::now() >= entry.expires {
            remove_right(name);
            false
        } else {
            true
        }
    });
    if entries.len() >= 32 {
        bail!("too many pending package approvals; wait and try again");
    }
    let mut random = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let name = format!("com.astronlab.scriptd.package.{}", hex::encode(random));
    let right = CString::new(name.clone())?;
    let keys = [
        "class",
        "group",
        "shared",
        "timeout",
        "allow-root",
        "authenticate-user",
    ]
    .map(CFString::from_str);
    let class = CFString::from_str("user");
    let group = CFString::from_str("admin");
    let timeout = CFNumber::new_i32(300);
    let no = unsafe { kCFBooleanFalse }.context("authorization boolean unavailable")?;
    let yes = unsafe { kCFBooleanTrue }.context("authorization boolean unavailable")?;
    let definition = CFDictionary::<CFString, CFType>::from_slices(
        &keys.iter().map(|key| key.as_ref()).collect::<Vec<_>>(),
        &[
            class.as_ref(),
            group.as_ref(),
            no.as_ref(),
            timeout.as_ref(),
            no.as_ref(),
            yes.as_ref(),
        ],
    );
    let description = CFString::from_str(&format!(
        "{} package {} from publisher {} for {}",
        if revoke { "Revoke" } else { "Approve" },
        query.package_identifier,
        query.publisher_team_identifier,
        identity.bundle_identifier
    ));
    let auth = Authorization::empty()?;
    let status = unsafe {
        AuthorizationRightSet(
            auth.0,
            right_pointer(&right),
            definition.as_ref(),
            Some(&description),
            None,
            None,
        )
    };
    if status != 0 {
        bail!("could not prepare package-specific administrator consent ({status})");
    }
    entries.insert(
        name.clone(),
        Pending {
            identity: identity.clone(),
            publisher: query.publisher_team_identifier.clone(),
            package: query.package_identifier.clone(),
            revoke,
            expires: Instant::now() + Duration::from_secs(300),
        },
    );
    Ok(name)
}

fn matches(entry: &Pending, identity: &Identity, request: &ApprovedRequest, revoke: bool) -> bool {
    entry.identity == *identity
        && entry.publisher == request.approval.publisher_team_identifier
        && entry.package == request.approval.package_identifier
        && entry.revoke == revoke
        && Instant::now() < entry.expires
}

pub(super) fn consume(identity: &Identity, request: &ApprovedRequest, revoke: bool) -> Result<()> {
    let entry = {
        let mut entries = pending()
            .lock()
            .map_err(|_| anyhow::anyhow!("package authorization state unavailable"))?;
        let entry = entries
            .get(&request.challenge)
            .context("package approval is absent, expired, or already consumed")?;
        if !matches(entry, identity, request, revoke) {
            bail!("package approval does not match the authenticated requester and package");
        }
        entries
            .remove(&request.challenge)
            .context("package approval disappeared")?
    };
    let result = validate_external(&request.challenge, &request.authorization);
    // Consume on success or failure. Cancellation and malformed forms cannot
    // leave a challenge usable by a later, unrelated grant request.
    remove_right(&request.challenge);
    drop(entry);
    result
}

fn validate_external(right: &str, bytes: &[i8]) -> Result<()> {
    let bytes: [i8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("administrator authorization is absent or malformed"))?;
    let external = AuthorizationExternalForm { bytes };
    let mut reference: AuthorizationRef = std::ptr::null();
    let status =
        unsafe { AuthorizationCreateFromExternalForm((&external).into(), (&mut reference).into()) };
    if status != 0 || reference.is_null() {
        bail!("administrator authorization could not be imported ({status})");
    }
    let auth = Authorization(reference);
    let name = CString::new(right)?;
    let mut item = AuthorizationItem {
        name: name.as_ptr(),
        valueLength: 0,
        value: std::ptr::null_mut(),
        flags: 0,
    };
    let rights = AuthorizationItemSet {
        count: 1,
        items: &mut item,
    };
    let status = unsafe {
        AuthorizationCopyRights(
            auth.0,
            (&rights).into(),
            std::ptr::null(),
            AuthorizationFlags::Defaults,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        bail!("the user did not authorize this package request ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            team_identifier: "FGRZTQB885".into(),
            bundle_identifier: "com.astronlab.macmodules.mbrew".into(),
        }
    }
    #[test]
    fn approval_is_bound_to_app_package_publisher_action_and_expiry() {
        let identity = identity();
        let request = ApprovedRequest {
            approval: InstallerApprovalQuery {
                publisher_team_identifier: "FGRZTQB885".into(),
                package_identifier: "com.example.package".into(),
            },
            challenge: "unused".into(),
            authorization: vec![],
        };
        let mut entry = Pending {
            identity: identity.clone(),
            publisher: request.approval.publisher_team_identifier.clone(),
            package: request.approval.package_identifier.clone(),
            revoke: false,
            expires: Instant::now() + Duration::from_secs(60),
        };
        assert!(matches(&entry, &identity, &request, false));
        assert!(!matches(&entry, &identity, &request, true));
        entry.package = "com.example.other".into();
        assert!(!matches(&entry, &identity, &request, false));
        entry.package = request.approval.package_identifier.clone();
        entry.identity.bundle_identifier = "com.example.other".into();
        assert!(!matches(&entry, &identity, &request, false));
        entry.identity = identity.clone();
        entry.expires = Instant::now();
        assert!(!matches(&entry, &identity, &request, false));
    }
    #[test]
    fn absent_cancelled_and_unrelated_forms_do_not_grant_rights() {
        assert!(validate_external("com.astronlab.scriptd.package.test", &[]).is_err());
        assert!(validate_external("com.astronlab.scriptd.package.test", &[0; 32]).is_err());
        let request = ApprovedRequest {
            approval: InstallerApprovalQuery {
                publisher_team_identifier: "FGRZTQB885".into(),
                package_identifier: "com.example.package".into(),
            },
            challenge: "not-issued".into(),
            authorization: vec![0; 32],
        };
        assert!(consume(&identity(), &request, false).is_err());
    }
}
