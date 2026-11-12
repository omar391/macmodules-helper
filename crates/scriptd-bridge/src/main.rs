#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use objc2_core_foundation::{CFData, CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_security::{
    kSecCSSigningInformation, kSecCodeInfoIdentifier, kSecCodeInfoTeamIdentifier,
    kSecCodeInfoUnique, kSecGuestAttributeAudit, kSecGuestAttributePid, SecCSFlags, SecCode,
    SecStaticCode,
};
use scriptd_bridge_protocol::{
    Capability, CapabilityReport, Operation, OperationReceipt, OperationRequest, OperationState,
    OperationStatusRequest, PairingReceipt, PairingRequest, PairingStatus,
    INSTALLER_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ptr::NonNull;
use std::sync::OnceLock;

mod installer;
mod package_authorization;

#[cfg(test)]
const BRIDGE_BINARY: &str = "/usr/local/libexec/scriptd-bridge";
const EXPECTED_TEAM_IDENTIFIER: &str = "FGRZTQB885";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECEIPTS: usize = 4096;
const MAX_RECEIPT_MESSAGE_BYTES: usize = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const DIRECT_APP_BUNDLE_IDENTIFIER: &str = "com.astronlab.scriptd";
const DIRECT_MODULE_BUNDLE_IDENTIFIERS: &[&str] = &[
    "com.astronlab.macmodules.mbrew",
    "com.astronlab.macmodules.mcpu",
    "com.astronlab.macmodules.mwifi",
    "com.astronlab.macmodules.miwatch",
];
const LOCAL_PEERTOKEN: libc::c_int = 0x006;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HelperProfile {
    Brew,
    Wifi,
    AllInOne,
}

impl HelperProfile {
    fn accepts_bundle(self, bundle_identifier: &str) -> bool {
        match self {
            Self::Brew => bundle_identifier == "com.astronlab.macmodules.mbrew",
            Self::Wifi => bundle_identifier == "com.astronlab.macmodules.mwifi",
            Self::AllInOne => bundle_identifier == DIRECT_APP_BUNDLE_IDENTIFIER,
        }
    }
}

static ACTIVE_PROFILE: OnceLock<HelperProfile> = OnceLock::new();

fn profile_component() -> &'static str {
    match ACTIVE_PROFILE.get().copied() {
        Some(HelperProfile::Brew) => "brew",
        Some(HelperProfile::Wifi) => "wifi",
        Some(HelperProfile::AllInOne) => "all-in-one",
        None => "legacy",
    }
}

fn state_file() -> PathBuf {
    if ACTIVE_PROFILE.get().is_none() {
        return PathBuf::from("/Library/Application Support/scriptd/bridge-state.json");
    }
    PathBuf::from(format!(
        "/Library/Application Support/scriptd/{}/bridge-state.json",
        profile_component()
    ))
}

fn socket_directory() -> PathBuf {
    if ACTIVE_PROFILE.get().is_none() {
        return PathBuf::from("/var/run/scriptd");
    }
    PathBuf::from("/var/run/scriptd").join(profile_component())
}

fn installation_receipt() -> PathBuf {
    if ACTIVE_PROFILE.get().is_none() {
        return PathBuf::from("/Library/Application Support/scriptd/bridge-installation.json");
    }
    PathBuf::from(format!(
        "/Library/Application Support/scriptd/{}/bridge-installation.json",
        profile_component()
    ))
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    val: [u32; 8],
}

fn is_direct_distribution_identity(bundle_identifier: &str) -> bool {
    bundle_identifier == DIRECT_APP_BUNDLE_IDENTIFIER
        || DIRECT_MODULE_BUNDLE_IDENTIFIERS.contains(&bundle_identifier)
}

fn allows_wifi_capability(bundle_identifier: &str) -> bool {
    match ACTIVE_PROFILE.get().copied() {
        Some(profile) => {
            matches!(profile, HelperProfile::Wifi | HelperProfile::AllInOne)
                && profile.accepts_bundle(bundle_identifier)
        }
        None => matches!(
            bundle_identifier,
            "com.astronlab.scriptd" | "com.astronlab.macmodules.mwifi"
        ),
    }
}

fn allows_installer_capability(bundle_identifier: &str) -> bool {
    match ACTIVE_PROFILE.get().copied() {
        Some(profile) => {
            matches!(profile, HelperProfile::Brew | HelperProfile::AllInOne)
                && profile.accepts_bundle(bundle_identifier)
        }
        None => matches!(
            bundle_identifier,
            "com.astronlab.scriptd" | "com.astronlab.macmodules.mbrew"
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    v: u32,
    id: String,
    op: String,
    #[serde(default)]
    repo: String,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    yaml: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    v: u32,
    id: String,
    ok: bool,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    team_identifier: String,
    bundle_identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pairing {
    team_identifier: String,
    bundle_identifier: String,
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRecord {
    identity: Identity,
    request: OperationRequest,
    receipt: OperationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallerGrant {
    pub(crate) app_identity: Identity,
    pub(crate) publisher_team_identifier: String,
    pub(crate) package_identifier: String,
    pub(crate) method: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallerApprovalQuery {
    publisher_team_identifier: String,
    package_identifier: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    pairings: BTreeMap<String, Pairing>,
    #[serde(default)]
    pairing_authorizations: BTreeMap<String, Identity>,
    #[serde(default)]
    installer_grants: BTreeMap<String, InstallerGrant>,
    operations: BTreeMap<String, OperationRecord>,
}

impl State {
    fn load(path: &Path) -> Result<Self> {
        let state = match read_root_file(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("parse protected bridge state")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self {
                schema: "scriptd-bridge-state/v1".to_string(),
                ..Self::default()
            },
            Err(error) => return Err(error).context("read protected bridge state"),
        };
        if state.schema != "scriptd-bridge-state/v1" {
            bail!("unsupported protected bridge state schema");
        }
        let mut state = state;
        state.mark_interrupted_unknown();
        Ok(state)
    }

    fn mark_interrupted_unknown(&mut self) {
        for record in self.operations.values_mut() {
            if matches!(
                record.receipt.state,
                OperationState::Accepted | OperationState::Running
            ) {
                record.receipt.state = OperationState::Unknown;
                record.receipt.message = Some(
                    "bridge restarted before recording the operation outcome; it was not replayed"
                        .to_string(),
                );
            }
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_STATE_BYTES {
            bail!("bridge state exceeds the maximum supported size; refusing the change");
        }
        write_root_atomic(path, &bytes)
    }

    fn require_pairing(&self, identity: &Identity) -> Result<()> {
        // Embedded service profiles are registered by SMAppService from the
        // owning signed app bundle. Their exact identity/profile pair is
        // checked by capabilities and every operation; no manual pairing state
        // is needed for these new builds.
        if let Some(profile) = ACTIVE_PROFILE.get().copied() {
            validate_identity(identity)?;
            if profile.accepts_bundle(&identity.bundle_identifier) {
                return Ok(());
            }
            bail!("the embedded helper rejected an application identity outside its profile");
        }
        let pairing = self
            .pairings
            .get(&identity.bundle_identifier)
            .context("this app is not paired with the bridge")?;
        if !pairing.active || pairing.team_identifier != identity.team_identifier {
            bail!("the active pairing does not match this app's signing identity");
        }
        Ok(())
    }

    fn installer_grant(
        &self,
        identity: &Identity,
        package_identifier: &str,
    ) -> Result<&InstallerGrant> {
        let key = installer_grant_key(identity, package_identifier);
        self.installer_grants.get(&key).context(
            "this package and publisher have not been approved for unattended installation",
        )
    }

    fn set_installer_grant(
        &mut self,
        grant: InstallerGrant,
        revoke: bool,
        path: &Path,
    ) -> Result<()> {
        self.set_installer_grant_with(grant, revoke, |state| state.save(path))
    }

    fn set_installer_grant_with(
        &mut self,
        grant: InstallerGrant,
        revoke: bool,
        mut persist: impl FnMut(&State) -> Result<()>,
    ) -> Result<()> {
        validate_identity(&grant.app_identity)?;
        if !allows_installer_capability(&grant.app_identity.bundle_identifier) {
            bail!(
                "package approval is available only to the all-in-one or Brew Manager direct app"
            );
        }
        validate_team_identifier(&grant.publisher_team_identifier)?;
        validate_package_identifier(&grant.package_identifier)?;
        if grant.method != "package_installer_v1" {
            bail!("unsupported privileged installer method");
        }
        let key = installer_grant_key(&grant.app_identity, &grant.package_identifier);
        if let Some(existing) = self.installer_grants.get(&key) {
            if !revoke && existing.publisher_team_identifier != grant.publisher_team_identifier {
                bail!("revoke the existing publisher approval before changing package publisher");
            }
            if revoke && existing.publisher_team_identifier != grant.publisher_team_identifier {
                bail!("publisher identity does not match the approved package grant");
            }
        }
        let previous = if revoke {
            self.installer_grants.remove(&key)
        } else {
            self.installer_grants.insert(key.clone(), grant.clone())
        };
        if previous.is_none() && revoke {
            bail!("no matching installer approval exists");
        }
        if let Err(error) = persist(self) {
            match previous {
                Some(previous) => {
                    self.installer_grants.insert(key, previous);
                }
                None => {
                    self.installer_grants.remove(&key);
                }
            }
            return Err(error).context("persist installer approval change");
        }
        Ok(())
    }

    fn pair(
        &mut self,
        identity: &Identity,
        request: PairingRequest,
        path: &Path,
    ) -> Result<PairingReceipt> {
        self.pair_with(identity, request, |state| state.save(path))
    }

    fn pair_with(
        &mut self,
        identity: &Identity,
        request: PairingRequest,
        mut persist: impl FnMut(&State) -> Result<()>,
    ) -> Result<PairingReceipt> {
        validate_identity(identity)?;
        if !is_direct_distribution_identity(&identity.bundle_identifier) {
            bail!("only direct-distribution MacModules identities may pair with the helper");
        }
        if !matches!(
            request.protocol_version,
            PROTOCOL_VERSION | INSTALLER_PROTOCOL_VERSION
        ) || request.bundle_identifier != identity.bundle_identifier
        {
            bail!("pairing request does not match the authenticated app or protocol");
        }
        if let Some(existing) = self.pairings.get(&identity.bundle_identifier) {
            if existing.active {
                if existing.team_identifier != identity.team_identifier {
                    bail!(
                        "replacing the paired signer requires revoking the existing pairing first"
                    );
                }
                return Ok(PairingReceipt {
                    signing_identity: identity.team_identifier.clone(),
                    bundle_identifier: identity.bundle_identifier.clone(),
                    protocol_version: request.protocol_version,
                    active: true,
                });
            }
        }
        if self.pairing_authorizations.get(&identity.bundle_identifier) != Some(identity) {
            bail!("a protected administrator approval is required before pairing");
        }
        let pairing = Pairing {
            team_identifier: identity.team_identifier.clone(),
            bundle_identifier: identity.bundle_identifier.clone(),
            active: true,
        };
        let previous = self
            .pairings
            .insert(identity.bundle_identifier.clone(), pairing);
        self.pairing_authorizations
            .remove(&identity.bundle_identifier);
        if let Err(error) = persist(self) {
            if let Some(previous) = previous {
                self.pairings
                    .insert(identity.bundle_identifier.clone(), previous);
            } else {
                self.pairings.remove(&identity.bundle_identifier);
            }
            self.pairing_authorizations
                .insert(identity.bundle_identifier.clone(), identity.clone());
            return Err(error).context("persist pairing before acknowledging it");
        }
        Ok(PairingReceipt {
            signing_identity: identity.team_identifier.clone(),
            bundle_identifier: identity.bundle_identifier.clone(),
            protocol_version: request.protocol_version,
            active: true,
        })
    }

    fn authorize_pairing(&mut self, identity: &Identity, path: &Path) -> Result<()> {
        self.authorize_pairing_with(identity, |state| state.save(path))
    }

    fn authorize_pairing_with(
        &mut self,
        identity: &Identity,
        mut persist: impl FnMut(&State) -> Result<()>,
    ) -> Result<()> {
        validate_identity(identity)?;
        if !is_direct_distribution_identity(&identity.bundle_identifier) {
            bail!("only direct-distribution MacModules identities may request pairing approval");
        }
        if self
            .pairings
            .get(&identity.bundle_identifier)
            .is_some_and(|pairing| pairing.active)
        {
            bail!("revoke the active pairing before approving a different pairing");
        }
        let previous = self
            .pairing_authorizations
            .insert(identity.bundle_identifier.clone(), identity.clone());
        if let Err(error) = persist(self) {
            if let Some(previous) = previous {
                self.pairing_authorizations
                    .insert(identity.bundle_identifier.clone(), previous);
            } else {
                self.pairing_authorizations
                    .remove(&identity.bundle_identifier);
            }
            return Err(error).context("persist protected pairing approval");
        }
        Ok(())
    }

    fn submit_with(
        &mut self,
        identity: &Identity,
        request: OperationRequest,
        mut persist: impl FnMut(&State) -> Result<()>,
        execute_operation: impl FnOnce(&Operation, &[InstallerGrant]) -> Result<()>,
    ) -> Result<OperationReceipt> {
        request
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid bridge operation: {error}"))?;
        self.require_pairing(identity)?;
        let installer_grants = match &request.operation {
            Operation::InstallApprovedPackage {
                package_identifier, ..
            } => {
                if !allows_installer_capability(&identity.bundle_identifier) {
                    bail!("this signed MacModules identity cannot install packages");
                }
                self.installer_grant(identity, package_identifier)?;
                self.installer_grants
                    .values()
                    .filter(|grant| grant.app_identity == *identity)
                    .cloned()
                    .collect::<Vec<_>>()
            }
            Operation::SetWifiNetwork { .. } => {
                if !allows_wifi_capability(&identity.bundle_identifier) {
                    bail!("this signed MacModules identity cannot change Wi-Fi networks");
                }
                Vec::new()
            }
        };
        let id = request.operation_id.as_str().to_string();
        if let Some(existing) = self.operations.get(&id) {
            if existing.identity != *identity || existing.request != request {
                bail!("operation ID is already bound to a different request or app");
            }
            return Ok(existing.receipt.clone());
        }
        if self.operations.len() >= MAX_RECEIPTS {
            bail!("bridge receipt storage is full; refusing new operations");
        }
        let mut record = OperationRecord {
            identity: identity.clone(),
            request: request.clone(),
            receipt: OperationReceipt {
                protocol_version: request.protocol_version,
                operation_id: request.operation_id.clone(),
                state: OperationState::Accepted,
                message: None,
            },
        };
        self.operations.insert(id.clone(), record.clone());
        if let Err(error) = persist(self) {
            self.operations.remove(&id);
            return Err(error).context("persist operation acceptance before acknowledging");
        }

        record.receipt.state = OperationState::Running;
        self.operations.insert(id.clone(), record.clone());
        if let Err(error) = persist(self) {
            record.receipt.state = OperationState::Unknown;
            record.receipt.message = Some("operation was accepted but not started".into());
            self.operations.insert(id, record);
            return Err(error).context("persist running operation before execution");
        }

        match execute_operation(&request.operation, &installer_grants) {
            Ok(()) => {
                record.receipt.state = OperationState::Succeeded;
                record.receipt.message = Some("operation completed".to_string());
            }
            Err(error) => {
                record.receipt.state = OperationState::Failed;
                record.receipt.message = Some(bounded_receipt_message(format!(
                    "operation failed: {error:#}"
                )));
            }
        }
        self.operations.insert(id.clone(), record.clone());
        if let Err(error) = persist(self) {
            record.receipt.state = OperationState::Unknown;
            record.receipt.message = Some("operation ran but its result could not be saved".into());
            self.operations.insert(id, record);
            return Err(error).context("persist operation outcome");
        }
        Ok(record.receipt)
    }

    fn status(
        &self,
        identity: &Identity,
        request: OperationStatusRequest,
    ) -> Result<OperationReceipt> {
        request
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid bridge status request: {error}"))?;
        match self.operations.get(request.operation_id.as_str()) {
            Some(record) if record.identity == *identity => Ok(record.receipt.clone()),
            Some(_) => bail!("operation receipt belongs to a different app"),
            None => Ok(OperationReceipt {
                protocol_version: request.protocol_version,
                operation_id: request.operation_id,
                state: OperationState::Unknown,
                message: Some("no operation with this ID is recorded".to_string()),
            }),
        }
    }

    fn unpair(&mut self, identity: &Identity, path: &Path) -> Result<()> {
        self.unpair_with(identity, |state| state.save(path))
    }

    fn unpair_with(
        &mut self,
        identity: &Identity,
        mut persist: impl FnMut(&State) -> Result<()>,
    ) -> Result<()> {
        let pairing = self
            .pairings
            .get_mut(&identity.bundle_identifier)
            .context("no pairing exists for this app")?;
        if pairing.team_identifier != identity.team_identifier {
            bail!("only the paired signing identity may revoke this pairing");
        }
        pairing.active = false;
        persist(self)
    }
}

fn validate_identity(identity: &Identity) -> Result<()> {
    let valid_team = !identity.team_identifier.is_empty()
        && identity.team_identifier.len() <= 64
        && identity
            .team_identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric());
    let valid_bundle = !identity.bundle_identifier.is_empty()
        && identity.bundle_identifier.len() <= 255
        && identity
            .bundle_identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    if !valid_team || !valid_bundle {
        bail!("pairing identity is invalid");
    }
    Ok(())
}

pub(crate) fn validate_team_identifier(identifier: &str) -> Result<()> {
    if identifier.is_empty()
        || identifier.len() > 64
        || !identifier.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        bail!("publisher signing team identifier is invalid");
    }
    Ok(())
}

fn validate_package_identifier(identifier: &str) -> Result<()> {
    if identifier.is_empty()
        || identifier.len() > 255
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("package identifier is invalid");
    }
    Ok(())
}

fn installer_grant_key(identity: &Identity, package_identifier: &str) -> String {
    format!(
        "{}:{}:{}",
        identity.team_identifier, identity.bundle_identifier, package_identifier
    )
}

fn respond(
    id: &str,
    ok: bool,
    state: &str,
    message: Option<String>,
    snapshot: Option<serde_json::Value>,
) -> Response {
    respond_version(PROTOCOL_VERSION, id, ok, state, message, snapshot)
}

fn respond_version(
    version: u32,
    id: &str,
    ok: bool,
    state: &str,
    message: Option<String>,
    snapshot: Option<serde_json::Value>,
) -> Response {
    Response {
        v: version,
        id: id.to_string(),
        ok,
        state: state.to_string(),
        message,
        snapshot,
    }
}

fn handle(
    request: Request,
    identity: Option<Identity>,
    admin_authorized: bool,
    state: &mut State,
    state_path: &Path,
) -> Response {
    handle_with_executor(
        request,
        identity,
        admin_authorized,
        state,
        state_path,
        execute,
    )
}

fn handle_with_executor(
    request: Request,
    identity: Option<Identity>,
    admin_authorized: bool,
    state: &mut State,
    state_path: &Path,
    execute_operation: impl FnOnce(&Operation, &[InstallerGrant]) -> Result<()>,
) -> Response {
    handle_with_state_io(
        request,
        identity,
        admin_authorized,
        state,
        state_path,
        |state| state.save(state_path),
        execute_operation,
    )
}

fn handle_with_state_io<F, P>(
    request: Request,
    identity: Option<Identity>,
    admin_authorized: bool,
    state: &mut State,
    state_path: &Path,
    persist: P,
    execute_operation: F,
) -> Response
where
    F: FnOnce(&Operation, &[InstallerGrant]) -> Result<()>,
    P: FnMut(&State) -> Result<()>,
{
    let protocol_version = request.v;
    let mut response = handle_inner(
        request,
        identity,
        admin_authorized,
        state,
        state_path,
        persist,
        execute_operation,
    );
    response.v = protocol_version;
    response
}

fn handle_inner<F, P>(
    request: Request,
    identity: Option<Identity>,
    admin_authorized: bool,
    state: &mut State,
    state_path: &Path,
    persist: P,
    execute_operation: F,
) -> Response
where
    F: FnOnce(&Operation, &[InstallerGrant]) -> Result<()>,
    P: FnMut(&State) -> Result<()>,
{
    if !matches!(request.v, PROTOCOL_VERSION | INSTALLER_PROTOCOL_VERSION) {
        return respond(
            &request.id,
            false,
            "rejected",
            Some("unsupported bridge protocol version".into()),
            None,
        );
    }
    match request.op.as_str() {
        "capabilities" => respond_version(
            request.v,
            &request.id,
            true,
            "completed",
            None,
            Some(
                serde_json::to_value(CapabilityReport {
                    protocol_version: request.v,
                    capabilities: identity
                        .as_ref()
                        .map(|identity| {
                            let bundle_identifier = identity.bundle_identifier.as_str();
                            let mut capabilities = Vec::new();
                            if allows_wifi_capability(bundle_identifier) {
                                capabilities.push(Capability::WifiNetworkChange);
                            }
                            if request.v == INSTALLER_PROTOCOL_VERSION
                                && allows_installer_capability(bundle_identifier)
                            {
                                capabilities.push(Capability::InstallerPackageV1);
                            }
                            capabilities
                        })
                        .unwrap_or_default(),
                })
                .unwrap_or(serde_json::Value::Null),
            ),
        ),
        "pair" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing request is incomplete".into()),
                    None,
                );
            };
            let pairing: PairingRequest = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid pairing request: {error}")),
                        None,
                    )
                }
            };
            if pairing.protocol_version != request.v {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing protocol does not match the bridge request".into()),
                    None,
                );
            }
            match state.pair(identity, pairing, state_path) {
                Ok(receipt) => respond(
                    &request.id,
                    true,
                    "completed",
                    None,
                    Some(serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null)),
                ),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "authorize_pairing" => {
            if !admin_authorized {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing approval requires administrator authorization".into()),
                    None,
                );
            }
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing approval request is incomplete".into()),
                    None,
                );
            };
            let identity: Identity = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid pairing approval: {error}")),
                        None,
                    )
                }
            };
            match state.authorize_pairing(&identity, state_path) {
                Ok(()) => respond(
                    &request.id,
                    true,
                    "completed",
                    Some("one pairing approval recorded".into()),
                    None,
                ),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "prepare_authorize_package"
        | "prepare_revoke_package"
        | "request_authorize_package"
        | "request_revoke_package" => {
            let Some(identity) = identity else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            if !allows_installer_capability(&identity.bundle_identifier) {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("package approval is unavailable to this app profile".into()),
                    None,
                );
            }
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("package approval request is incomplete".into()),
                    None,
                );
            };
            if request.op.starts_with("prepare_") {
                let result = (|| -> Result<String> {
                    state.require_pairing(&identity)?;
                    let query: InstallerApprovalQuery = serde_json::from_str(payload)?;
                    package_authorization::prepare(
                        &identity,
                        &query,
                        request.op == "prepare_revoke_package",
                    )
                })();
                return match result {
                    Ok(challenge) => respond(
                        &request.id,
                        true,
                        "completed",
                        None,
                        Some(serde_json::json!({"challenge": challenge})),
                    ),
                    Err(error) => respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(error.to_string()),
                        None,
                    ),
                };
            }
            let authorized: package_authorization::ApprovedRequest =
                match serde_json::from_str(payload) {
                    Ok(value) => value,
                    Err(error) => {
                        return respond(
                            &request.id,
                            false,
                            "rejected",
                            Some(format!(
                                "package-specific user authorization is required: {error}"
                            )),
                            None,
                        )
                    }
                };
            let revoke = request.op == "request_revoke_package";
            if let Err(error) = state
                .require_pairing(&identity)
                .and_then(|()| package_authorization::consume(&identity, &authorized, revoke))
            {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                );
            }
            let query = authorized.approval;
            let grant = InstallerGrant {
                app_identity: identity,
                publisher_team_identifier: query.publisher_team_identifier,
                package_identifier: query.package_identifier,
                method: "package_installer_v1".into(),
            };
            match state.set_installer_grant(grant, revoke, state_path) {
                Ok(()) => respond(
                    &request.id,
                    true,
                    "completed",
                    Some(
                        if revoke {
                            "future package authorization revoked"
                        } else {
                            "package publisher authorization recorded"
                        }
                        .into(),
                    ),
                    None,
                ),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "authorize_package" | "revoke_package" => {
            if !admin_authorized {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("package approval changes require administrator authorization".into()),
                    None,
                );
            }
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("package approval request is incomplete".into()),
                    None,
                );
            };
            let grant: InstallerGrant = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid package approval: {error}")),
                        None,
                    )
                }
            };
            match state.set_installer_grant(grant, request.op == "revoke_package", state_path) {
                Ok(()) => respond(
                    &request.id,
                    true,
                    "completed",
                    Some(
                        if request.op == "revoke_package" {
                            "future package authorization revoked"
                        } else {
                            "package publisher authorization recorded"
                        }
                        .into(),
                    ),
                    None,
                ),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "package_approval_status" | "package_approval_list" => {
            if request.v != INSTALLER_PROTOCOL_VERSION {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("package approvals require bridge protocol version 4".into()),
                    None,
                );
            }
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            if !allows_installer_capability(&identity.bundle_identifier) {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(
                        "installer approvals are available only to the direct-download app".into(),
                    ),
                    None,
                );
            }
            if let Err(error) = state.require_pairing(identity) {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                );
            }
            if request.op == "package_approval_status" {
                let Some(payload) = request.yaml.as_deref() else {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some("package approval query is incomplete".into()),
                        None,
                    );
                };
                let query: InstallerApprovalQuery = match serde_json::from_str(payload) {
                    Ok(value) => value,
                    Err(error) => {
                        return respond(
                            &request.id,
                            false,
                            "rejected",
                            Some(format!("invalid package approval query: {error}")),
                            None,
                        )
                    }
                };
                if validate_team_identifier(&query.publisher_team_identifier).is_err()
                    || validate_package_identifier(&query.package_identifier).is_err()
                {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some("package approval identity is invalid".into()),
                        None,
                    );
                }
                let approved = state
                    .installer_grant(identity, &query.package_identifier)
                    .is_ok_and(|grant| {
                        grant.publisher_team_identifier == query.publisher_team_identifier
                    });
                respond_version(
                    request.v,
                    &request.id,
                    true,
                    "completed",
                    None,
                    Some(serde_json::json!({ "approved": approved })),
                )
            } else {
                let approvals = state
                    .installer_grants
                    .values()
                    .filter(|grant| {
                        grant.app_identity == *identity && grant.method == "package_installer_v1"
                    })
                    .map(|grant| {
                        serde_json::json!({
                            "publisher_team_identifier": grant.publisher_team_identifier,
                            "package_identifier": grant.package_identifier,
                        })
                    })
                    .collect::<Vec<_>>();
                respond_version(
                    request.v,
                    &request.id,
                    true,
                    "completed",
                    None,
                    Some(serde_json::Value::Array(approvals)),
                )
            }
        }
        "pairing_status" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            if request.module.as_deref() != Some(identity.bundle_identifier.as_str()) {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing status is limited to the authenticated app".into()),
                    None,
                );
            }
            let active = pairing_is_active(ACTIVE_PROFILE.get().copied(), identity, state);
            let status = PairingStatus {
                protocol_version: request.v,
                bundle_identifier: identity.bundle_identifier.clone(),
                active,
            };
            respond(
                &request.id,
                true,
                "completed",
                None,
                Some(serde_json::to_value(status).unwrap_or(serde_json::Value::Null)),
            )
        }
        "unpair" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            if request.module.as_deref() != Some(identity.bundle_identifier.as_str()) {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("an app may revoke only its own pairing".into()),
                    None,
                );
            }
            match state.unpair(identity, state_path) {
                Ok(()) => respond(
                    &request.id,
                    true,
                    "completed",
                    Some("pairing revoked".into()),
                    None,
                ),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "operation" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("operation request is incomplete".into()),
                    None,
                );
            };
            let operation: OperationRequest = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid operation request: {error}")),
                        None,
                    )
                }
            };
            if operation.protocol_version != request.v {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("operation protocol does not match the bridge request".into()),
                    None,
                );
            }
            match state.submit_with(identity, operation, persist, execute_operation) {
                Ok(receipt) => operation_response(&request.id, receipt),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "operation_status" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("operation status request is incomplete".into()),
                    None,
                );
            };
            let status: OperationStatusRequest = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid status request: {error}")),
                        None,
                    )
                }
            };
            match state.status(identity, status) {
                Ok(receipt) => operation_response(&request.id, receipt),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        _ => respond(
            &request.id,
            false,
            "rejected",
            Some("unsupported bridge operation".into()),
            None,
        ),
    }
}

fn bounded_receipt_message(mut message: String) -> String {
    if message.len() > MAX_RECEIPT_MESSAGE_BYTES {
        let mut end = MAX_RECEIPT_MESSAGE_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    message
}

fn operation_response(id: &str, receipt: OperationReceipt) -> Response {
    let state = match receipt.state {
        OperationState::Accepted => "accepted",
        OperationState::Running => "running",
        OperationState::Succeeded => "completed",
        OperationState::Failed => "failed",
        OperationState::Unavailable => "unavailable",
        OperationState::Unknown => "unknown",
    };
    let mut response = respond(
        id,
        true,
        state,
        receipt.message.clone(),
        Some(serde_json::to_value(&receipt).unwrap_or(serde_json::Value::Null)),
    );
    response.v = receipt.protocol_version;
    response
}

fn execute(operation: &Operation, grants: &[InstallerGrant]) -> Result<()> {
    match operation {
        Operation::SetWifiNetwork { ssid } => {
            let ports = Command::new("/usr/sbin/networksetup")
                .arg("-listallhardwareports")
                .output()
                .context("read Wi-Fi hardware device")?;
            if !ports.status.success() {
                bail!("networksetup could not enumerate hardware ports");
            }
            let mut device = None;
            let mut in_wifi = false;
            for line in String::from_utf8_lossy(&ports.stdout).lines() {
                if let Some(value) = line.trim().strip_prefix("Hardware Port:") {
                    in_wifi = matches!(value.trim(), "Wi-Fi" | "AirPort");
                } else if in_wifi {
                    if let Some(value) = line.trim().strip_prefix("Device:") {
                        device = Some(value.trim().to_string());
                        break;
                    }
                }
            }
            let device = device.context("no Wi-Fi hardware device was found")?;
            if device.is_empty()
                || device.len() > 32
                || !device
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                bail!("Wi-Fi hardware device name is invalid");
            }
            let result = Command::new("/usr/sbin/networksetup")
                .args(["-setairportnetwork", device.as_str(), ssid])
                .output()
                .context("ask macOS to join the requested Wi-Fi network")?;
            if !result.status.success() {
                bail!("networksetup failed with status {}", result.status);
            }
            Ok(())
        }
        Operation::InstallApprovedPackage {
            package_identifier,
            package_path,
        } => installer::install_approved_package(package_identifier, package_path, grants),
    }
}

fn configure_accepted_stream(stream: &UnixStream) -> Result<()> {
    stream
        .set_nonblocking(false)
        .context("restore blocking mode on accepted bridge stream")?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .context("set bridge client read timeout")?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .context("set bridge client write timeout")?;
    Ok(())
}

fn serve() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("the bridge service must run as root");
    }
    verify_installation()?;
    let state_path = state_file();
    let state_directory = state_path
        .parent()
        .context("bridge state path has no profile directory")?;
    fs::create_dir_all(state_directory).context("create profile state directory")?;
    fs::set_permissions(state_directory, fs::Permissions::from_mode(0o700))
        .context("protect profile state directory")?;
    let socket_directory = socket_directory();
    fs::create_dir_all(&socket_directory).context("create protected bridge socket directory")?;
    let directory_metadata = fs::symlink_metadata(&socket_directory)?;
    if !directory_metadata.is_dir()
        || directory_metadata.uid() != 0
        || directory_metadata.mode() & 0o022 != 0
    {
        bail!("bridge socket directory must be protected and root-owned");
    }
    let mut state = State::load(&state_path)?;
    let mut active = None;
    loop {
        let uid = match console_uid() {
            Ok(uid) => uid,
            Err(error) => {
                if let Some(previous) = active.take() {
                    remove_console_listener(previous)?;
                }
                eprintln!("console user is unavailable; bridge socket is closed: {error:#}");
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        if !matches!(active.as_ref(), Some(listener) if listener.uid == uid) {
            if let Err(error) =
                replace_console_listener(&mut active, &socket_directory, uid, chown_socket)
            {
                eprintln!("could not bind bridge for console user {uid}: {error:#}");
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        }
        let Some(listener) = active.as_ref() else {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        match listener.listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(error) = configure_accepted_stream(&stream) {
                    eprintln!("could not configure accepted bridge stream: {error:#}");
                    continue;
                }
                let expected_uid = listener.uid;
                let response = match read_request(&stream, expected_uid) {
                    Ok((request, identity, admin_authorized))
                        if console_uid().ok() == Some(expected_uid) =>
                    {
                        handle(request, identity, admin_authorized, &mut state, &state_path)
                    }
                    Ok(_) => respond(
                        "unknown",
                        false,
                        "rejected",
                        Some("console user changed while the request was pending".to_string()),
                        None,
                    ),
                    Err(error) => {
                        respond("unknown", false, "rejected", Some(error.to_string()), None)
                    }
                };
                let _ = write_response(&mut stream, &response);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("accept bridge client"),
        }
    }
}

fn read_request(
    stream: &UnixStream,
    expected_uid: u32,
) -> Result<(Request, Option<Identity>, bool)> {
    let uid = peer_uid(stream)?;
    let pid = peer_pid(stream)?;
    let audit_token = peer_audit_token(stream)?;
    let request = read_request_frame(stream)?;
    if matches!(
        request.op.as_str(),
        "authorize_pairing" | "authorize_package" | "revoke_package"
    ) {
        if uid != 0 {
            bail!("administrator approval requires a root-owned bridge client");
        }
        let client_identity = authenticate_peer_token(pid, audit_token)?;
        let bridge_identity = authenticate_peer_identity_path(&std::env::current_exe()?)?;
        if client_identity != bridge_identity {
            bail!("administrator approval must come from the installed bridge executable");
        }
        return Ok((request, None, true));
    }
    if uid != expected_uid {
        bail!("bridge peer user was not accepted");
    }
    let identity = if operation_requires_peer_identity(request.op.as_str()) {
        Some(authenticate_peer_token(pid, audit_token)?)
    } else {
        None
    };
    Ok((request, identity, false))
}

fn operation_requires_peer_identity(op: &str) -> bool {
    matches!(
        op,
        "capabilities"
            | "pair"
            | "pairing_status"
            | "unpair"
            | "operation"
            | "operation_status"
            | "package_approval_status"
            | "package_approval_list"
            | "prepare_authorize_package"
            | "prepare_revoke_package"
            | "request_authorize_package"
            | "request_revoke_package"
    )
}

fn pairing_is_active(profile: Option<HelperProfile>, identity: &Identity, state: &State) -> bool {
    if profile.is_some_and(|profile| profile.accepts_bundle(&identity.bundle_identifier)) {
        return true;
    }
    state
        .pairings
        .get(&identity.bundle_identifier)
        .is_some_and(|pairing| {
            pairing.active && pairing.team_identifier == identity.team_identifier
        })
}

fn read_request_frame(stream: &UnixStream) -> Result<Request> {
    let mut stream = stream;
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte)?;
        if read == 0 || byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= MAX_REQUEST_BYTES {
            bail!("bridge request exceeds the size limit");
        }
        bytes.push(byte[0]);
    }
    serde_json::from_slice(&bytes).context("parse bridge request")
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read bridge peer user");
    }
    Ok(uid)
}

fn peer_pid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    } != 0
        || pid <= 0
    {
        return Err(std::io::Error::last_os_error()).context("read bridge peer process");
    }
    Ok(pid as u32)
}

fn peer_audit_token(stream: &UnixStream) -> Result<Option<AuditToken>> {
    use std::os::fd::AsRawFd;
    let mut token = AuditToken { val: [0; 8] };
    let mut length = std::mem::size_of_val(&token) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            LOCAL_PEERTOKEN,
            (&mut token as *mut AuditToken).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("read bridge peer audit token");
    }
    if length as usize != std::mem::size_of::<AuditToken>() {
        bail!("bridge peer audit token has an unexpected size");
    }
    Ok(Some(token))
}

#[cfg(test)]
fn authenticate_peer(pid: u32) -> Result<Identity> {
    authenticate_peer_token(pid, None)
}

fn authenticate_peer_token(pid: u32, audit_token: Option<AuditToken>) -> Result<Identity> {
    const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;
    extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_void,
            buffersize: u32,
        ) -> libc::c_int;
    }
    let mut path_bytes = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE as usize];
    let length = unsafe {
        proc_pidpath(
            pid as libc::c_int,
            path_bytes.as_mut_ptr().cast(),
            PROC_PIDPATHINFO_MAXSIZE,
        )
    };
    if length <= 0 {
        return Err(std::io::Error::last_os_error()).context("resolve bridge peer executable");
    }
    path_bytes.truncate(length as usize);
    let executable = PathBuf::from(
        String::from_utf8(path_bytes).context("bridge peer executable path is not UTF-8")?,
    );
    if has_mas_receipt(&executable) {
        bail!("the Mac App Store edition cannot use Scriptd Bridge operations");
    }
    // Use the kernel-bound PID for every codesign query so pathname replacement
    // cannot switch identities between metadata and distribution verification.
    let process_reference = process_code_reference(pid);
    let (security_identifier, security_team, security_cdhash) =
        security_identity_for_process(pid, audit_token)?;
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--all-architectures", "--"])
        .arg(&process_reference)
        .output()
        .context("verify bridge peer code signature")?;
    if !verify.status.success() {
        bail!("bridge peer code signature is invalid");
    }
    let details = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4", "--"])
        .arg(&process_reference)
        .output()
        .context("read bridge peer signing identity")?;
    if !details.status.success() {
        bail!("bridge peer signing identity is unavailable");
    }
    let details = String::from_utf8_lossy(&details.stderr);
    let mut identifier = None;
    let mut team = None;
    let mut signature = None;
    let mut cdhash = None;
    for line in details.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            identifier = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("TeamIdentifier=") {
            team = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("Signature=") {
            signature = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("CDHash=") {
            cdhash = Some(value.trim().to_ascii_lowercase());
        }
    }
    let team = team
        .filter(|value| !value.is_empty() && value != "not set")
        .context("bridge peer must have a distribution signer")?;
    if team != EXPECTED_TEAM_IDENTIFIER {
        bail!("bridge peer was signed by an unexpected team");
    }
    let identifier = identifier.context("bridge peer has no bundle identifier")?;
    let cdhash = cdhash.context("bridge peer signature has no code-directory hash")?;
    if identifier != security_identifier || team != security_team || cdhash != security_cdhash {
        bail!("bridge peer executable changed during identity verification");
    }
    if signature.as_deref() == Some("adhoc") {
        bail!("ad-hoc signed apps cannot pair with the bridge");
    }
    let requirement = developer_id_requirement(&team, &identifier)?;
    let verify_distribution = Command::new("/usr/bin/codesign")
        .args([
            "--verify",
            "--strict",
            "--all-architectures",
            "-R",
            &requirement,
            "--",
        ])
        .arg(&process_reference)
        .output()
        .context("verify bridge peer Developer ID distribution identity")?;
    if !verify_distribution.status.success() {
        bail!("bridge peer must be signed for Developer ID distribution");
    }
    Ok(Identity {
        team_identifier: team,
        bundle_identifier: identifier,
    })
}

fn security_identity_for_process(
    pid: u32,
    audit_token: Option<AuditToken>,
) -> Result<(String, String, String)> {
    let pid_value = CFNumber::new_i32(pid as i32);
    let pid_key = unsafe { kSecGuestAttributePid };
    let audit_data = audit_token.map(|token| {
        let bytes = unsafe {
            std::slice::from_raw_parts(token.val.as_ptr().cast::<u8>(), token.val.len() * 4)
        };
        CFData::from_bytes(bytes)
    });
    let typed_attributes = if let Some(audit_data) = audit_data.as_ref() {
        let key = unsafe { kSecGuestAttributeAudit };
        CFDictionary::<CFString, CFType>::from_slices(&[key], &[audit_data.as_ref()])
    } else {
        CFDictionary::<CFString, CFType>::from_slices(&[pid_key], &[pid_value.as_ref()])
    };
    let attributes: &CFDictionary = unsafe {
        &*(typed_attributes.as_ref() as *const CFDictionary<CFString, CFType>
            as *const CFDictionary)
    };
    let mut guest_pointer: *mut SecCode = std::ptr::null_mut();
    let status = unsafe {
        SecCode::copy_guest_with_attributes(
            None,
            Some(attributes),
            SecCSFlags(0),
            NonNull::from(&mut guest_pointer),
        )
    };
    if status != 0 {
        bail!("resolve bridge peer code identity: security status {status}");
    }
    let guest_pointer = NonNull::new(guest_pointer)
        .context("security framework returned a null bridge peer code reference")?;
    let guest: CFRetained<SecCode> = unsafe { CFRetained::from_raw(guest_pointer) };
    let validity = unsafe { guest.check_validity(SecCSFlags(0), None) };
    if validity != 0 {
        bail!("bridge peer code signature is invalid: security status {validity}");
    }
    let mut static_pointer: *const SecStaticCode = std::ptr::null();
    let status =
        unsafe { guest.copy_static_code(SecCSFlags(0), NonNull::from(&mut static_pointer)) };
    if status != 0 {
        bail!("resolve bridge peer static code: security status {status}");
    }
    let static_pointer = NonNull::new(static_pointer.cast_mut())
        .context("security framework returned null static code")?;
    let static_code: CFRetained<SecStaticCode> = unsafe { CFRetained::from_raw(static_pointer) };
    let mut information_pointer: *const CFDictionary = std::ptr::null();
    let status = unsafe {
        SecCode::copy_signing_information(
            &static_code,
            SecCSFlags(kSecCSSigningInformation),
            NonNull::from(&mut information_pointer),
        )
    };
    if status != 0 {
        bail!("read bridge peer signing information: security status {status}");
    }
    let information_pointer = NonNull::new(information_pointer.cast_mut())
        .context("security framework returned null signing information")?;
    let information: CFRetained<CFDictionary<CFString, CFType>> =
        unsafe { CFRetained::cast_unchecked(CFRetained::from_raw(information_pointer)) };
    let string_value = |key: &'static CFString, label: &str| -> Result<String> {
        information
            .get(key)
            .and_then(|value| value.downcast::<CFString>().ok())
            .map(|value| value.to_string())
            .context(format!(
                "bridge peer signing information is missing {label}"
            ))
    };
    let team = string_value(unsafe { kSecCodeInfoTeamIdentifier }, "the team identifier")?;
    let identifier = string_value(unsafe { kSecCodeInfoIdentifier }, "the identifier")?;
    let cdhash = information
        .get(unsafe { kSecCodeInfoUnique })
        .and_then(|value| value.downcast::<CFData>().ok())
        .context("bridge peer signing information is missing the CDHash")?;
    Ok((identifier, team, hex::encode(cdhash.to_vec())))
}

fn developer_id_requirement(team: &str, identifier: &str) -> Result<String> {
    if team.is_empty()
        || !team.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || identifier.is_empty()
        || identifier.chars().any(char::is_control)
    {
        bail!("bridge peer signing identity contains invalid requirement values");
    }
    let quote_requirement_value =
        |value: &str| format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""));
    // codesign -R treats a bare argument as a file path; '=' marks source text.
    Ok(format!(
        "=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = {} and identifier {}",
        quote_requirement_value(team),
        quote_requirement_value(identifier)
    ))
}

fn process_code_reference(pid: u32) -> String {
    format!("+{pid}")
}

fn has_mas_receipt(executable: &Path) -> bool {
    executable
        .ancestors()
        .find(|ancestor| {
            ancestor
                .extension()
                .is_some_and(|extension| extension == "app")
        })
        .is_some_and(|bundle| bundle.join("Contents/_MASReceipt/receipt").is_file())
}

fn read_root_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "bridge state must be a protected root-owned file",
        ));
    }
    if metadata.len() > MAX_STATE_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bridge state exceeds the maximum supported size",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bridge state exceeds the maximum supported size",
        ));
    }
    Ok(bytes)
}

fn write_root_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("bridge state has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("bridge state directory must be protected and root-owned");
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationReceipt {
    schema: String,
    protocol_version: u32,
    binary_sha256: String,
    team_identifier: String,
    bundle_identifier: String,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn verify_installation() -> Result<()> {
    if ACTIVE_PROFILE.get().is_some() {
        let executable = std::env::current_exe()?;
        if !executable
            .to_string_lossy()
            .contains("/Contents/MacOS/scriptd-bridge")
        {
            bail!("embedded helper is not running from its containing app bundle");
        }
        let identity = authenticate_peer_identity_path(&executable)?;
        if identity.team_identifier != EXPECTED_TEAM_IDENTIFIER {
            bail!("embedded helper was not signed by the expected development team");
        }
        return Ok(());
    }
    let receipt_path = installation_receipt();
    let receipt_bytes =
        read_root_file(&receipt_path).context("read bridge installation receipt")?;
    let receipt: InstallationReceipt = serde_json::from_slice(&receipt_bytes)?;
    let binary = std::env::current_exe()?;
    let binary_bytes = fs::read(&binary)?;
    let identity = authenticate_peer_identity_path(&binary)?;
    if receipt.schema != "scriptd-bridge-installation/v1"
        || receipt.protocol_version != PROTOCOL_VERSION
        || receipt.binary_sha256 != digest(&binary_bytes)
        || receipt.team_identifier != identity.team_identifier
        || receipt.bundle_identifier != identity.bundle_identifier
    {
        bail!("bridge installation receipt does not match the installed binary");
    }
    Ok(())
}

fn authenticate_peer_identity_path(executable: &Path) -> Result<Identity> {
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--all-architectures", "--"])
        .arg(executable)
        .output()?;
    if !verify.status.success() {
        bail!("installed bridge code signature is invalid");
    }
    let details = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4", "--"])
        .arg(executable)
        .output()?;
    if !details.status.success() {
        bail!("installed bridge signing identity is unavailable");
    }
    let details = String::from_utf8_lossy(&details.stderr);
    let mut identifier = None;
    let mut team = None;
    for line in details.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            identifier = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("TeamIdentifier=") {
            team = Some(value.trim().to_string());
        }
    }
    Ok(Identity {
        team_identifier: team
            .filter(|value| value != "not set")
            .context("installed bridge has no distribution signer")?,
        bundle_identifier: identifier.context("installed bridge has no bundle identifier")?,
    })
}

fn write_installation_receipt() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("writing the bridge installation receipt requires administrator privileges");
    }
    let binary_path = std::env::current_exe()?;
    let metadata = fs::symlink_metadata(&binary_path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("installed bridge executable must be protected and root-owned");
    }
    let receipt_path = installation_receipt();
    let parent = receipt_path
        .parent()
        .context("bridge receipt directory missing")?;
    match fs::create_dir(parent) {
        Ok(()) => fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create profile installation directory"),
    }
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        bail!("bridge receipt directory must be protected and root-owned");
    }
    let identity = authenticate_peer_identity_path(&binary_path)?;
    let receipt = InstallationReceipt {
        schema: "scriptd-bridge-installation/v1".to_string(),
        protocol_version: PROTOCOL_VERSION,
        binary_sha256: digest(&fs::read(&binary_path)?),
        team_identifier: identity.team_identifier,
        bundle_identifier: identity.bundle_identifier,
    };
    write_root_atomic(&installation_receipt(), &serde_json::to_vec(&receipt)?)
}

pub(crate) fn console_uid() -> Result<u32> {
    let output = Command::new("/usr/bin/stat")
        .args(["-f", "%u", "/dev/console"])
        .output()?;
    if !output.status.success() {
        bail!("could not resolve the logged-in console user");
    }
    parse_console_uid(&String::from_utf8_lossy(&output.stdout))
}

fn parse_console_uid(value: &str) -> Result<u32> {
    value
        .trim()
        .parse()
        .context("console user ID is not a valid number")
}

struct ConsoleListener {
    uid: u32,
    path: PathBuf,
    listener: UnixListener,
}

fn socket_path(directory: &Path, uid: u32) -> PathBuf {
    directory.join(format!("scriptd-broker-{uid}.sock"))
}

fn chown_socket(path: &Path, uid: u32) -> Result<()> {
    let socket_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::chown(socket_c.as_ptr(), uid, !0 as libc::gid_t) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("assign bridge socket to console user");
    }
    Ok(())
}

fn bind_console_listener(
    directory: &Path,
    uid: u32,
    assign_owner: impl FnOnce(&Path, u32) -> Result<()>,
) -> Result<ConsoleListener> {
    let socket = socket_path(directory, uid);
    match fs::symlink_metadata(&socket) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || (metadata.uid() != 0 && metadata.uid() != uid) {
                bail!("existing bridge socket path is not a protected socket");
            }
            if UnixStream::connect(&socket).is_ok() {
                bail!("bridge is already running");
            }
            fs::remove_file(&socket).context("remove stale bridge socket")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect bridge socket path"),
    }
    let listener =
        UnixListener::bind(&socket).with_context(|| format!("bind {}", socket.display()))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    assign_owner(&socket, uid)?;
    listener.set_nonblocking(true)?;
    Ok(ConsoleListener {
        uid,
        path: socket,
        listener,
    })
}

fn remove_console_listener(listener: ConsoleListener) -> Result<()> {
    let ConsoleListener {
        uid,
        path,
        listener,
    } = listener;
    drop(listener);
    match fs::symlink_metadata(&path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && (metadata.uid() == 0 || metadata.uid() == uid) =>
        {
            fs::remove_file(path).context("remove previous console-user bridge socket")
        }
        Ok(_) => bail!("bridge socket changed type or owner during user transition"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect previous console-user bridge socket"),
    }
}

fn replace_console_listener(
    active: &mut Option<ConsoleListener>,
    directory: &Path,
    uid: u32,
    assign_owner: impl Fn(&Path, u32) -> Result<()>,
) -> Result<()> {
    if active.as_ref().is_some_and(|listener| listener.uid == uid) {
        return Ok(());
    }
    if let Some(previous) = active.take() {
        remove_console_listener(previous)?;
    }
    *active = Some(bind_console_listener(directory, uid, assign_owner)?);
    Ok(())
}

fn write_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let mut bytes = serde_json::to_vec(response)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if let Some(index) = args.iter().position(|argument| argument == "--profile") {
        let profile = args
            .get(index + 1)
            .context("missing helper profile value")?
            .as_str();
        let parsed = match profile {
            "brew" => HelperProfile::Brew,
            "wifi" => HelperProfile::Wifi,
            "all-in-one" => HelperProfile::AllInOne,
            _ => bail!("unsupported helper profile"),
        };
        ACTIVE_PROFILE
            .set(parsed)
            .map_err(|_| anyhow::anyhow!("helper profile was configured more than once"))?;
        args.drain(index..=index + 1);
    }
    let command = if args.is_empty() {
        Some("serve".to_owned())
    } else {
        args.first().cloned()
    };
    let mut args = args.into_iter().skip(usize::from(command.is_some()));
    match command.as_deref() {
        Some("serve") => serve(),
        Some("write-installation-receipt") => write_installation_receipt(),
        Some("authorize-pairing") => {
            let team_identifier = args.next().context("missing team identifier")?;
            let bundle_identifier = args.next().context("missing bundle identifier")?;
            if args.next().is_some() {
                bail!("too many authorize-pairing arguments");
            }
            authorize_pairing_command(team_identifier, bundle_identifier)
        }
        Some("set-package-approval") => {
            let action = args.next().context("missing approve or revoke action")?;
            let app_team = args.next().context("missing app team identifier")?;
            let app_bundle = args.next().context("missing app bundle identifier")?;
            let publisher_team = args
                .next()
                .context("missing package publisher team identifier")?;
            let package_identifier = args.next().context("missing package identifier")?;
            if args.next().is_some() || !matches!(action.as_str(), "approve" | "revoke") {
                bail!("usage: set-package-approval <approve|revoke> <app-team> <app-bundle> <publisher-team> <package-id>");
            }
            set_package_approval_command(
                action == "revoke",
                app_team,
                app_bundle,
                publisher_team,
                package_identifier,
            )
        }
        _ => {
            eprintln!("usage: scriptd-bridge serve|write-installation-receipt|authorize-pairing <team-identifier> <bundle-identifier>|set-package-approval <approve|revoke> <app-team> <app-bundle> <publisher-team> <package-id>");
            std::process::exit(2);
        }
    }
}

fn authorize_pairing_command(team_identifier: String, bundle_identifier: String) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("pairing approval requires administrator privileges");
    }
    let identity = Identity {
        team_identifier,
        bundle_identifier,
    };
    validate_identity(&identity)?;
    let uid = console_uid()?;
    let socket_directory = socket_directory();
    let socket = socket_path(&socket_directory, uid);
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("connect to bridge at {}", socket.display()))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = Request {
        v: PROTOCOL_VERSION,
        id: format!("authorize-{}", std::process::id()),
        op: "authorize_pairing".to_string(),
        repo: String::new(),
        module: None,
        yaml: Some(serde_json::to_string(&identity)?),
    };
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    let mut response_bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let count = stream.read(&mut byte)?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        if response_bytes.len() >= MAX_REQUEST_BYTES {
            bail!("bridge approval response exceeds the size limit");
        }
        response_bytes.push(byte[0]);
    }
    let response: Response =
        serde_json::from_slice(&response_bytes).context("parse bridge approval response")?;
    if !response.ok || response.state != "completed" {
        bail!(
            "bridge rejected pairing approval: {}",
            response.message.unwrap_or_else(|| response.state.clone())
        );
    }
    println!(
        "{} for {} signed by {}",
        response
            .message
            .unwrap_or_else(|| "pairing approval recorded".to_string()),
        identity.bundle_identifier,
        identity.team_identifier,
    );
    Ok(())
}

fn set_package_approval_command(
    revoke: bool,
    app_team: String,
    app_bundle: String,
    publisher_team: String,
    package_identifier: String,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("package approval changes require administrator privileges");
    }
    let grant = InstallerGrant {
        app_identity: Identity {
            team_identifier: app_team,
            bundle_identifier: app_bundle,
        },
        publisher_team_identifier: publisher_team,
        package_identifier,
        method: "package_installer_v1".into(),
    };
    validate_identity(&grant.app_identity)?;
    validate_team_identifier(&grant.publisher_team_identifier)?;
    validate_package_identifier(&grant.package_identifier)?;
    let uid = console_uid()?;
    let socket_directory = socket_directory();
    let socket = socket_path(&socket_directory, uid);
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("connect to bridge at {}", socket.display()))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = Request {
        v: PROTOCOL_VERSION,
        id: format!("package-approval-{}", std::process::id()),
        op: if revoke {
            "revoke_package"
        } else {
            "authorize_package"
        }
        .into(),
        repo: String::new(),
        module: None,
        yaml: Some(serde_json::to_string(&grant)?),
    };
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    let mut response_bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let count = stream.read(&mut byte)?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        if response_bytes.len() >= MAX_REQUEST_BYTES {
            bail!("bridge approval response exceeds the size limit");
        }
        response_bytes.push(byte[0]);
    }
    let response: Response = serde_json::from_slice(&response_bytes)
        .context("parse bridge package approval response")?;
    if !response.ok || response.state != "completed" {
        bail!(
            "bridge rejected package approval: {}",
            response.message.unwrap_or_else(|| response.state.clone())
        );
    }
    println!(
        "{} for {} from {}",
        response
            .message
            .unwrap_or_else(|| "package approval changed".into()),
        grant.package_identifier,
        grant.publisher_team_identifier
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            team_identifier: "TEAM123456".to_string(),
            bundle_identifier: DIRECT_APP_BUNDLE_IDENTIFIER.to_string(),
        }
    }

    fn paired_state(active: bool) -> State {
        let identity = identity();
        State {
            schema: "scriptd-bridge-state/v1".to_string(),
            pairings: BTreeMap::from([(
                identity.bundle_identifier.clone(),
                Pairing {
                    team_identifier: identity.team_identifier,
                    bundle_identifier: identity.bundle_identifier,
                    active,
                },
            )]),
            ..State::default()
        }
    }

    fn operation_request(id: &str) -> OperationRequest {
        OperationRequest {
            protocol_version: PROTOCOL_VERSION,
            operation_id: scriptd_bridge_protocol::OperationId::new(id)
                .expect("valid operation ID"),
            operation: Operation::SetWifiNetwork {
                ssid: "Saved network".to_string(),
            },
        }
    }

    fn smoke_request(
        id: &str,
        op: &str,
        payload: Option<String>,
        version: u32,
    ) -> Result<Response> {
        let request = Request {
            v: version,
            id: id.to_string(),
            op: op.to_string(),
            repo: String::new(),
            module: None,
            yaml: payload,
        };
        let socket_directory = socket_directory();
        let socket = socket_path(&socket_directory, console_uid()?);
        let mut stream = UnixStream::connect(&socket)
            .with_context(|| format!("connect to running bridge at {}", socket.display()))?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        stream.write_all(&bytes)?;

        let mut response_bytes = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            let count = stream.read(&mut byte)?;
            if count == 0 || byte[0] == b'\n' {
                break;
            }
            if response_bytes.len() >= MAX_REQUEST_BYTES {
                anyhow::bail!("bridge smoke response exceeds the size limit");
            }
            response_bytes.push(byte[0]);
        }
        let response: Response = serde_json::from_slice(&response_bytes)?;
        if response.id != id {
            anyhow::bail!("bridge returned a response for a different request");
        }
        Ok(response)
    }

    fn installer_smoke_operation(
        id: &str,
        package_identifier: &str,
        package_path: &str,
    ) -> OperationRequest {
        OperationRequest {
            protocol_version: INSTALLER_PROTOCOL_VERSION,
            operation_id: scriptd_bridge_protocol::OperationId::new(id)
                .expect("valid installer smoke operation ID"),
            operation: Operation::InstallApprovedPackage {
                package_identifier: package_identifier.to_string(),
                package_path: package_path.to_string(),
            },
        }
    }

    fn smoke_admin(arguments: &[&str]) {
        let output = Command::new("/usr/bin/sudo")
            .arg("-n")
            .arg(BRIDGE_BINARY)
            .args(arguments)
            .output()
            .expect("run bridge administrator command");
        assert!(
            output.status.success(),
            "bridge administrator command failed: {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn smoke_receipt(response: Response) -> OperationReceipt {
        assert!(response.ok, "bridge request failed: {:?}", response.message);
        serde_json::from_value(response.snapshot.expect("operation receipt"))
            .expect("decode operation receipt")
    }

    fn smoke_approval_status(publisher: &str, package: &str) -> bool {
        let query = InstallerApprovalQuery {
            publisher_team_identifier: publisher.to_string(),
            package_identifier: package.to_string(),
        };
        let response = smoke_request(
            "status-smoke-approval",
            "package_approval_status",
            Some(serde_json::to_string(&query).expect("serialize approval query")),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("query durable package approval");
        assert!(
            response.ok,
            "approval status failed: {:?}",
            response.message
        );
        response
            .snapshot
            .expect("package approval status")
            .get("approved")
            .and_then(serde_json::Value::as_bool)
            .expect("boolean package approval result")
    }

    struct SmokeService {
        child: std::process::Child,
        pid_file: PathBuf,
        service_pid: u32,
    }

    impl SmokeService {
        fn start() -> Self {
            let pid_file = PathBuf::from(
                std::env::var_os("SCRIPTD_INSTALLER_SMOKE_SERVICE_PID_FILE")
                    .expect("service pid file path"),
            );
            let _ = fs::remove_file(&pid_file);
            let mut child = Command::new("/usr/bin/sudo")
                .arg("-n")
                .arg("/bin/sh")
                .arg("-c")
                .arg("printf '%s\\n' \"$$\" > \"$1\"; exec \"$2\" serve")
                .arg("scriptd-installer-smoke-service")
                .arg(&pid_file)
                .arg(BRIDGE_BINARY)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .expect("start isolated bridge service");
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            let service_pid = loop {
                if let Ok(value) = fs::read_to_string(&pid_file) {
                    if let Ok(pid) = value.trim().parse::<u32>() {
                        break pid;
                    }
                }
                if let Some(status) = child.try_wait().expect("inspect bridge process") {
                    panic!("bridge service exited before startup: {status}");
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "bridge service did not publish its process ID"
                );
                std::thread::sleep(Duration::from_millis(100));
            };
            let socket = socket_path(&socket_directory(), console_uid().expect("console user"));
            loop {
                if UnixStream::connect(&socket).is_ok() {
                    break;
                }
                if let Some(status) = child.try_wait().expect("inspect bridge process") {
                    panic!("bridge service exited before binding its socket: {status}");
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "bridge service did not bind its console-user socket"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Self {
                child,
                pid_file,
                service_pid,
            }
        }

        fn stop(&mut self, signal: &str) {
            let pid = self.service_pid.to_string();
            let output = Command::new("/usr/bin/sudo")
                .args(["-n", "/bin/kill", signal, pid.as_str()])
                .output()
                .expect("signal isolated bridge service");
            assert!(
                output.status.success(),
                "could not signal bridge service: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let _ = self.child.wait().expect("wait for bridge service exit");
        }
    }

    impl Drop for SmokeService {
        fn drop(&mut self) {
            if self.child.try_wait().is_ok_and(|status| status.is_none()) {
                let pid = self.service_pid.to_string();
                let _ = Command::new("/usr/bin/sudo")
                    .args(["-n", "/bin/kill", "-TERM", pid.as_str()])
                    .status();
                let _ = self.child.wait();
            }
            let owns_pid_file = fs::read_to_string(&self.pid_file)
                .is_ok_and(|value| value.trim() == self.service_pid.to_string());
            if owns_pid_file {
                let _ = fs::remove_file(&self.pid_file);
            }
        }
    }

    fn smoke_operation_state(operation_id: &str) -> Option<String> {
        let output = Command::new("/usr/bin/sudo")
            .arg("-n")
            .arg(state_file())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let state: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
        state["operations"][operation_id]["receipt"]["state"]
            .as_str()
            .map(str::to_string)
    }

    fn wait_for_file(path: &Path, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if path.is_file() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("timed out waiting for {}", path.display());
    }

    #[test]
    #[ignore = "requires signed notarized packages and a disposable macOS runner"]
    fn installer_transaction_survives_upgrade_restart_and_revocation() {
        let package_v1 = std::env::var("SCRIPTD_INSTALLER_SMOKE_PACKAGE_V1")
            .expect("version 1 smoke package path");
        let package_v2 = std::env::var("SCRIPTD_INSTALLER_SMOKE_PACKAGE_V2")
            .expect("version 2 smoke package path");
        let package_v3 = std::env::var("SCRIPTD_INSTALLER_SMOKE_PACKAGE_V3")
            .expect("version 3 smoke package path");
        let publisher = std::env::var("SCRIPTD_INSTALLER_SMOKE_PUBLISHER")
            .expect("smoke package publisher team");
        let directory = tempfile::tempdir().expect("create isolated substitution fixtures");
        let package_identifier = "com.astronlab.scriptd.installer-smoke.pkg";
        let dependency_identifier = "com.astronlab.scriptd.installer-smoke.dependency.pkg";
        let marker = Path::new("/private/tmp/scriptd-installer-smoke/marker");
        let dependency_marker = Path::new("/private/tmp/scriptd-installer-smoke-dependency/marker");
        let interrupted_started = Path::new("/private/tmp/scriptd-installer-smoke-v3-started");
        let interrupted_runs = Path::new("/private/tmp/scriptd-installer-smoke-v3-runs");
        let identity = authenticate_peer(std::process::id())
            .expect("authenticate signed smoke client process");
        assert_eq!(identity.bundle_identifier, DIRECT_APP_BUNDLE_IDENTIFIER);

        let mut service = SmokeService::start();
        smoke_admin(&[
            "authorize-pairing",
            &identity.team_identifier,
            &identity.bundle_identifier,
        ]);
        let pairing = smoke_request(
            "pair-smoke-app",
            "pair",
            Some(
                serde_json::to_string(&PairingRequest {
                    bundle_identifier: identity.bundle_identifier.clone(),
                    protocol_version: INSTALLER_PROTOCOL_VERSION,
                })
                .expect("serialize pairing request"),
            ),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("pair signed smoke client");
        assert!(pairing.ok, "app pairing failed: {:?}", pairing.message);

        for package in [package_identifier, dependency_identifier] {
            smoke_admin(&[
                "set-package-approval",
                "approve",
                &identity.team_identifier,
                &identity.bundle_identifier,
                &publisher,
                package,
            ]);
            assert!(smoke_approval_status(&publisher, package));
        }

        let request_v1 =
            installer_smoke_operation("smoke-install-v1", package_identifier, &package_v1);
        let response = smoke_request(
            "submit-smoke-v1",
            "operation",
            Some(serde_json::to_string(&request_v1).expect("serialize v1 operation")),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("submit version 1 package");
        let receipt_v1 = smoke_receipt(response);
        assert_eq!(receipt_v1.state, OperationState::Succeeded);
        assert!(
            dependency_marker.is_file(),
            "approved dependency was not installed"
        );
        assert_eq!(
            fs::read_to_string(marker).expect("read v1 marker").trim(),
            "version 1"
        );

        let status = smoke_request(
            "status-smoke-v1",
            "operation_status",
            Some(
                serde_json::to_string(&OperationStatusRequest {
                    protocol_version: INSTALLER_PROTOCOL_VERSION,
                    operation_id: request_v1.operation_id.clone(),
                })
                .expect("serialize completed operation status query"),
            ),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("read completed operation status");
        assert_eq!(smoke_receipt(status).state, OperationState::Succeeded);

        service.stop("-TERM");
        service = SmokeService::start();
        assert!(smoke_approval_status(&publisher, package_identifier));
        assert!(smoke_approval_status(&publisher, dependency_identifier));
        let duplicate = smoke_request(
            "retry-smoke-v1-after-restart",
            "operation",
            Some(serde_json::to_string(&request_v1).expect("serialize duplicate operation")),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("reconcile duplicate operation after restart");
        assert_eq!(smoke_receipt(duplicate), receipt_v1);
        assert_eq!(
            fs::read_to_string(marker)
                .expect("marker after cross-restart duplicate")
                .trim(),
            "version 1",
            "a duplicate operation replayed the completed installer"
        );

        let request_v2 =
            installer_smoke_operation("smoke-upgrade-v2", package_identifier, &package_v2);
        let upgrade = smoke_request(
            "submit-smoke-v2",
            "operation",
            Some(serde_json::to_string(&request_v2).expect("serialize v2 operation")),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("submit version 2 package upgrade");
        assert_eq!(smoke_receipt(upgrade).state, OperationState::Succeeded);
        assert_eq!(
            fs::read_to_string(marker).expect("read v2 marker").trim(),
            "version 2"
        );

        smoke_admin(&[
            "set-package-approval",
            "revoke",
            &identity.team_identifier,
            &identity.bundle_identifier,
            &publisher,
            dependency_identifier,
        ]);
        let request_missing_dependency = installer_smoke_operation(
            "smoke-missing-dependency-grant",
            package_identifier,
            &package_v2,
        );
        let rejected_dependency = smoke_request(
            "submit-missing-dependency-grant",
            "operation",
            Some(
                serde_json::to_string(&request_missing_dependency)
                    .expect("serialize missing-dependency operation"),
            ),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("submit package with unapproved dependency");
        assert_eq!(
            smoke_receipt(rejected_dependency).state,
            OperationState::Failed
        );
        assert_eq!(
            fs::read_to_string(marker)
                .expect("marker after dependency rejection")
                .trim(),
            "version 2"
        );
        smoke_admin(&[
            "set-package-approval",
            "approve",
            &identity.team_identifier,
            &identity.bundle_identifier,
            &publisher,
            dependency_identifier,
        ]);

        smoke_admin(&[
            "set-package-approval",
            "revoke",
            &identity.team_identifier,
            &identity.bundle_identifier,
            &publisher,
            package_identifier,
        ]);
        let wrong_publisher = "WRONGTEAM1";
        smoke_admin(&[
            "set-package-approval",
            "approve",
            &identity.team_identifier,
            &identity.bundle_identifier,
            wrong_publisher,
            package_identifier,
        ]);
        let request_wrong_publisher =
            installer_smoke_operation("smoke-wrong-publisher", package_identifier, &package_v2);
        let rejected_publisher = smoke_request(
            "submit-wrong-publisher",
            "operation",
            Some(
                serde_json::to_string(&request_wrong_publisher)
                    .expect("serialize wrong-publisher operation"),
            ),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("submit package with wrong publisher approval");
        assert_eq!(
            smoke_receipt(rejected_publisher).state,
            OperationState::Failed
        );
        assert_eq!(
            fs::read_to_string(marker)
                .expect("marker after publisher rejection")
                .trim(),
            "version 2"
        );
        smoke_admin(&[
            "set-package-approval",
            "revoke",
            &identity.team_identifier,
            &identity.bundle_identifier,
            wrong_publisher,
            package_identifier,
        ]);
        smoke_admin(&[
            "set-package-approval",
            "approve",
            &identity.team_identifier,
            &identity.bundle_identifier,
            &publisher,
            package_identifier,
        ]);

        let tampered_package = directory.path().join("tampered.pkg");
        fs::copy(&package_v2, &tampered_package).expect("copy package substitution fixture");
        OpenOptions::new()
            .append(true)
            .open(&tampered_package)
            .expect("open package substitution fixture")
            .write_all(b"substituted")
            .expect("alter package substitution fixture");
        let chown = Command::new("/usr/sbin/chown")
            .arg(
                console_uid()
                    .expect("find disposable runner console user")
                    .to_string(),
            )
            .arg(&tampered_package)
            .status()
            .expect("set user ownership on tampered package fixture");
        assert!(chown.success(), "tampered package ownership setup failed");
        let tampered = installer_smoke_operation(
            "smoke-tampered-package",
            package_identifier,
            tampered_package
                .to_str()
                .expect("UTF-8 package fixture path"),
        );
        let tampered_response = smoke_request(
            "submit-tampered-package",
            "operation",
            Some(serde_json::to_string(&tampered).expect("serialize tampered operation")),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("submit tampered package");
        assert_eq!(
            smoke_receipt(tampered_response).state,
            OperationState::Failed
        );
        assert_eq!(
            fs::read_to_string(marker)
                .expect("read marker after tampered package rejection")
                .trim(),
            "version 2"
        );

        let substituted_path = directory.path().join("substituted.pkg");
        std::os::unix::fs::symlink(&package_v2, &substituted_path)
            .expect("create package path substitution fixture");
        let substituted = installer_smoke_operation(
            "smoke-substituted-path",
            package_identifier,
            substituted_path.to_str().expect("UTF-8 substituted path"),
        );
        let substituted_response = smoke_request(
            "submit-substituted-path",
            "operation",
            Some(
                serde_json::to_string(&substituted).expect("serialize substituted-path operation"),
            ),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("submit symlink-substituted package path");
        assert_eq!(
            smoke_receipt(substituted_response).state,
            OperationState::Failed
        );
        assert_eq!(
            fs::read_to_string(marker)
                .expect("read marker after path rejection")
                .trim(),
            "version 2"
        );

        let request_v3 =
            installer_smoke_operation("smoke-interrupted-v3", package_identifier, &package_v3);
        let request_for_thread = request_v3.clone();
        let submit = std::thread::spawn(move || {
            smoke_request(
                "submit-interrupted-v3",
                "operation",
                Some(serde_json::to_string(&request_for_thread).expect("serialize v3 operation")),
                INSTALLER_PROTOCOL_VERSION,
            )
        });
        wait_for_file(interrupted_started, Duration::from_secs(30));
        assert_eq!(
            smoke_operation_state(request_v3.operation_id.as_str()).as_deref(),
            Some("running"),
            "the broker did not durably record the in-flight transaction"
        );
        let staged_package = Path::new("/Library/Application Support/scriptd/packages")
            .join(format!("scriptd-{}/approved.pkg", service.service_pid));
        let replacement = directory.path().join("replacement.pkg");
        fs::copy(&tampered_package, &replacement).expect("prepare staged-content substitution");
        let replacement_owner = Command::new("/usr/sbin/chown")
            .arg(console_uid().expect("console user").to_string())
            .arg(&replacement)
            .status()
            .expect("set substitution fixture ownership");
        assert!(replacement_owner.success());
        let substitution = fs::rename(&replacement, &staged_package)
            .expect_err("unprivileged client replaced the protected staged package");
        assert_eq!(substitution.kind(), std::io::ErrorKind::PermissionDenied);

        service.stop("-KILL");
        assert!(
            submit
                .join()
                .expect("join interrupted client submission")
                .is_err(),
            "interrupted client unexpectedly received a completed response"
        );
        std::thread::sleep(Duration::from_secs(9));
        service = SmokeService::start();
        let interrupted_status = smoke_request(
            "status-interrupted-v3",
            "operation_status",
            Some(
                serde_json::to_string(&OperationStatusRequest {
                    protocol_version: INSTALLER_PROTOCOL_VERSION,
                    operation_id: request_v3.operation_id.clone(),
                })
                .expect("serialize interrupted operation status"),
            ),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("read reconciled interrupted operation");
        assert_eq!(
            smoke_receipt(interrupted_status).state,
            OperationState::Unknown
        );
        let retry_interrupted = smoke_request(
            "retry-interrupted-v3-after-restart",
            "operation",
            Some(serde_json::to_string(&request_v3).expect("serialize interrupted retry")),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("reconcile duplicate interrupted operation");
        assert_eq!(
            smoke_receipt(retry_interrupted).state,
            OperationState::Unknown
        );
        assert_eq!(
            fs::read_to_string(interrupted_runs)
                .expect("read interrupted installer invocation marker")
                .lines()
                .count(),
            1,
            "restart replayed an operation with an uncertain outcome"
        );

        smoke_admin(&[
            "set-package-approval",
            "revoke",
            &identity.team_identifier,
            &identity.bundle_identifier,
            &publisher,
            package_identifier,
        ]);
        service.stop("-TERM");
        service = SmokeService::start();
        assert!(!smoke_approval_status(&publisher, package_identifier));
        let after_revoke =
            installer_smoke_operation("smoke-after-revocation", package_identifier, &package_v2);
        let rejected = smoke_request(
            "submit-after-revocation",
            "operation",
            Some(
                serde_json::to_string(&after_revoke).expect("serialize post-revocation operation"),
            ),
            INSTALLER_PROTOCOL_VERSION,
        )
        .expect("submit operation after durable grant revocation");
        assert!(!rejected.ok, "revoked package authorization was accepted");
        service.stop("-TERM");
    }

    #[test]
    fn pairing_uses_authenticated_signer_and_refuses_silent_replacement() {
        let identity = identity();
        let mut state = State {
            schema: "scriptd-bridge-state/v1".to_string(),
            ..State::default()
        };
        let request = PairingRequest {
            bundle_identifier: identity.bundle_identifier.clone(),
            protocol_version: PROTOCOL_VERSION,
        };
        assert!(state
            .pair_with(&identity, request.clone(), |_| Ok(()))
            .is_err());
        state
            .authorize_pairing_with(&identity, |_| Ok(()))
            .expect("record protected administrator approval");
        let replacement = Identity {
            team_identifier: "OTHERTEAM".to_string(),
            bundle_identifier: identity.bundle_identifier.clone(),
        };
        assert!(state
            .pair_with(&replacement, request.clone(), |_| Ok(()))
            .is_err());
        let receipt = state
            .pair_with(&identity, request.clone(), |_| Ok(()))
            .expect("pair signed app");
        assert!(receipt.active);
        assert_eq!(receipt.signing_identity, identity.team_identifier);
        assert!(!state
            .pairing_authorizations
            .contains_key(&identity.bundle_identifier));
        assert!(state.pair_with(&replacement, request, |_| Ok(())).is_err());
        assert_eq!(
            state.pairings[&identity.bundle_identifier].team_identifier,
            identity.team_identifier
        );
    }

    #[test]
    fn v4_pairing_and_status_preserve_the_requested_protocol_version() {
        let identity = identity();
        let mut state = State::default();
        state
            .authorize_pairing_with(&identity, |_| Ok(()))
            .expect("record administrator approval");
        let request = PairingRequest {
            bundle_identifier: identity.bundle_identifier.clone(),
            protocol_version: INSTALLER_PROTOCOL_VERSION,
        };
        let receipt = state
            .pair_with(&identity, request, |_| Ok(()))
            .expect("pair v4 client");
        assert_eq!(receipt.protocol_version, INSTALLER_PROTOCOL_VERSION);

        let response = handle(
            Request {
                v: INSTALLER_PROTOCOL_VERSION,
                id: "pairing-status-v4".into(),
                op: "pairing_status".into(),
                repo: String::new(),
                module: Some(identity.bundle_identifier.clone()),
                yaml: None,
            },
            Some(identity.clone()),
            false,
            &mut state,
            Path::new("unused"),
        );
        assert!(response.ok);
        assert_eq!(response.v, INSTALLER_PROTOCOL_VERSION);
        let status: PairingStatus =
            serde_json::from_value(response.snapshot.unwrap()).expect("decode v4 pairing status");
        assert_eq!(status.protocol_version, INSTALLER_PROTOCOL_VERSION);
        assert!(status.active);
    }

    #[test]
    fn pairing_rejects_payload_version_mismatch_with_request_envelope() {
        let identity = identity();
        let mut state = State::default();
        let response = handle(
            Request {
                v: PROTOCOL_VERSION,
                id: "pair-version-mismatch".into(),
                op: "pair".into(),
                repo: String::new(),
                module: None,
                yaml: Some(
                    serde_json::to_string(&PairingRequest {
                        bundle_identifier: identity.bundle_identifier.clone(),
                        protocol_version: INSTALLER_PROTOCOL_VERSION,
                    })
                    .expect("serialize mismatched pairing request"),
                ),
            },
            Some(identity),
            false,
            &mut state,
            Path::new("unused"),
        );
        assert!(!response.ok);
        assert!(response
            .message
            .unwrap()
            .contains("does not match the bridge request"));
    }

    #[test]
    fn revoked_pairing_requires_a_new_approval_before_reactivation() {
        let identity = identity();
        let request = PairingRequest {
            bundle_identifier: identity.bundle_identifier.clone(),
            protocol_version: PROTOCOL_VERSION,
        };
        let mut state = State::default();
        state
            .authorize_pairing_with(&identity, |_| Ok(()))
            .expect("approve initial pairing");
        state
            .pair_with(&identity, request.clone(), |_| Ok(()))
            .expect("activate approved pairing");
        state
            .unpair_with(&identity, |_| Ok(()))
            .expect("revoke pairing");

        assert!(state
            .pair_with(&identity, request.clone(), |_| Ok(()))
            .is_err());
        let unrelated = Identity {
            team_identifier: "OTHERTEAM".to_string(),
            bundle_identifier: identity.bundle_identifier.clone(),
        };
        assert!(state
            .pair_with(&unrelated, request.clone(), |_| Ok(()))
            .is_err());

        state
            .authorize_pairing_with(&identity, |_| Ok(()))
            .expect("renew approval after revocation");
        assert!(
            state
                .pair_with(&identity, request, |_| Ok(()))
                .expect("reactivate with renewed approval")
                .active
        );
    }

    #[test]
    fn older_persisted_state_defaults_to_no_pairing_approvals() {
        let state: State = serde_json::from_str(
            r#"{"schema":"scriptd-bridge-state/v1","pairings":{},"operations":{}}"#,
        )
        .expect("load state written before approval support");
        assert!(state.pairing_authorizations.is_empty());
    }

    #[test]
    fn oversized_state_is_rejected_before_persistence() {
        let state = State {
            schema: "x".repeat(MAX_STATE_BYTES + 1),
            ..State::default()
        };
        let error = state
            .save(Path::new("unused"))
            .expect_err("oversized state must fail before touching the path");
        assert!(error
            .to_string()
            .contains("exceeds the maximum supported size"));
    }

    #[test]
    fn multibyte_installer_failure_receipts_stay_within_protocol_limit() {
        let message = bounded_receipt_message(format!("operation failed: {}", "界".repeat(2048)));
        assert!(message.len() <= MAX_RECEIPT_MESSAGE_BYTES);
        let operation_id = scriptd_bridge_protocol::OperationId::new("multibyte-failure")
            .expect("valid operation ID");
        let receipt = OperationReceipt {
            protocol_version: INSTALLER_PROTOCOL_VERSION,
            operation_id: operation_id.clone(),
            state: OperationState::Failed,
            message: Some(message),
        };
        receipt
            .validate_for(&operation_id)
            .expect("bounded failure receipt validates");
    }

    #[test]
    fn pairing_approval_rejects_requests_without_root_authorization() {
        let identity = identity();
        let request = Request {
            v: PROTOCOL_VERSION,
            id: "approve".to_string(),
            op: "authorize_pairing".to_string(),
            repo: String::new(),
            module: None,
            yaml: Some(serde_json::to_string(&identity).expect("serialize identity")),
        };
        let rejected = handle(
            request,
            None,
            false,
            &mut State::default(),
            Path::new("unused"),
        );
        assert!(!rejected.ok);
    }

    #[test]
    fn isolated_socket_to_handler_to_injected_executor_to_correlated_receipt() {
        // Isolated versions of the real serve-loop seams: `bind_console_listener`
        // binds a temp socket, raw bytes use the production frame decoder,
        // the operation goes through the production handler with fixture
        // authentication and a recording executor, and the correlated
        // receipt plus status lookup come back by operation ID. Peer codesign
        // authentication cannot run for this unprivileged fixture, so the
        // test supplies the identity after decoding the same wire bytes. The
        // production `read_request` authentication path and allowlists remain
        // unchanged and are covered by their existing rejection tests.
        let directory = tempfile::tempdir().expect("create isolated socket directory");
        let state_directory = tempfile::tempdir().expect("create isolated state directory");
        let expected_uid = unsafe { libc::geteuid() };
        let listener = bind_console_listener(directory.path(), expected_uid, |_, _| Ok(()))
            .expect("bind isolated console-user socket");
        listener
            .listener
            .set_nonblocking(false)
            .expect("blocking accept");
        let state_path = state_directory.path().join("state.json");
        let mut state = State::load(&state_path).expect("load isolated state");
        let app_identity = identity();
        // Simulated administrator approval with a fixture identity.
        state
            .authorize_pairing_with(&app_identity, |_| Ok(()))
            .expect("approve fixture pairing");
        state
            .pair_with(
                &app_identity,
                PairingRequest {
                    bundle_identifier: app_identity.bundle_identifier.clone(),
                    protocol_version: PROTOCOL_VERSION,
                },
                |_| Ok(()),
            )
            .expect("pair fixture identity");

        // 1) Wire round trip over the real socket framing: capabilities.
        let mut client = UnixStream::connect(socket_path(directory.path(), expected_uid))
            .expect("connect isolated client");
        client
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("client read timeout");
        client
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("client write timeout");
        let mut request_bytes = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            id: "wire-capabilities".to_string(),
            op: "capabilities".to_string(),
            repo: String::new(),
            module: None,
            yaml: None,
        })
        .expect("serialize wire request");
        request_bytes.push(b'\n');
        client
            .write_all(&request_bytes)
            .expect("write wire request");
        let (mut accepted, _) = listener.listener.accept().expect("accept isolated client");
        configure_accepted_stream(&accepted).expect("configure accepted stream");
        // Capabilities now require the signed peer. This fixture is not that
        // peer, so the framing check stops at the production frame decoder.
        let wire_request = read_request_frame(&accepted).expect("read wire request");
        assert_eq!(wire_request.id, "wire-capabilities");
        assert!(operation_requires_peer_identity(&wire_request.op));
        let response = handle(
            wire_request,
            Some(app_identity.clone()),
            false,
            &mut state,
            &state_path,
        );
        assert!(response.ok, "handler rejected: {:?}", response.message);
        write_response(&mut accepted, &response).expect("write wire response");
        let mut response_bytes = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let count = client.read(&mut byte).expect("read wire response");
            if count == 0 || byte[0] == b'\n' {
                break;
            }
            response_bytes.push(byte[0]);
        }
        let read_back: Response =
            serde_json::from_slice(&response_bytes).expect("decode wire response");
        assert_eq!(read_back.id, "wire-capabilities");
        assert!(read_back.ok);
        let report: CapabilityReport =
            serde_json::from_value(read_back.snapshot.clone().expect("capability snapshot"))
                .expect("decode capability report");
        assert_eq!(report.capabilities, vec![Capability::WifiNetworkChange]);
        drop(client);

        // 2) Operation wire bytes through the production frame decoder and
        // handler, with fixture authentication and an injected executor.
        let operation = operation_request("socket-correlated");
        let operation_request = Request {
            v: PROTOCOL_VERSION,
            id: "wire-operation".to_string(),
            op: "operation".to_string(),
            repo: String::new(),
            module: None,
            yaml: Some(serde_json::to_string(&operation).expect("serialize operation request")),
        };
        let executed = std::cell::Cell::new(0);
        let mut operation_bytes =
            serde_json::to_vec(&operation_request).expect("serialize wire operation");
        operation_bytes.push(b'\n');
        let mut operation_client = UnixStream::connect(socket_path(directory.path(), expected_uid))
            .expect("connect operation client");
        operation_client
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("operation read timeout");
        operation_client
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("operation write timeout");
        operation_client
            .write_all(&operation_bytes)
            .expect("write operation request");
        let (mut operation_accepted, _) =
            listener.listener.accept().expect("accept operation client");
        configure_accepted_stream(&operation_accepted).expect("configure operation stream");
        let wire_operation =
            read_request_frame(&operation_accepted).expect("decode operation wire request");
        assert_eq!(wire_operation.id, "wire-operation");
        assert_eq!(wire_operation.op, "operation");
        let response = handle_with_state_io(
            wire_operation,
            Some(app_identity.clone()),
            false,
            &mut state,
            &state_path,
            |_| Ok(()),
            |operation, grants| {
                assert!(grants.is_empty());
                assert_eq!(
                    *operation,
                    Operation::SetWifiNetwork {
                        ssid: "Saved network".to_string()
                    }
                );
                executed.set(executed.get() + 1);
                Ok(())
            },
        );
        assert!(response.ok, "handler rejected: {:?}", response.message);
        write_response(&mut operation_accepted, &response).expect("write operation response");
        let mut operation_response_bytes = Vec::new();
        loop {
            let count = operation_client
                .read(&mut byte)
                .expect("read operation response");
            if count == 0 || byte[0] == b'\n' {
                break;
            }
            operation_response_bytes.push(byte[0]);
        }
        let operation_response_readback: Response =
            serde_json::from_slice(&operation_response_bytes).expect("decode operation response");
        assert!(operation_response_readback.ok);
        let receipt: OperationReceipt = serde_json::from_value(
            operation_response_readback
                .snapshot
                .clone()
                .expect("operation receipt snapshot"),
        )
        .expect("decode operation receipt");
        assert_eq!(executed.get(), 1);
        assert_eq!(receipt.operation_id.as_str(), "socket-correlated");
        assert_eq!(receipt.state, OperationState::Succeeded);
        assert_eq!(receipt.protocol_version, PROTOCOL_VERSION);
        // 3) Correlation: replay returns the same receipt without
        // executing again, and status lookup by original ID matches.
        drop(operation_client);
        let replay_response = handle_with_state_io(
            Request {
                v: PROTOCOL_VERSION,
                id: "wire-operation-replay".to_string(),
                op: "operation".to_string(),
                repo: String::new(),
                module: None,
                yaml: Some(serde_json::to_string(&operation).expect("serialize replay")),
            },
            Some(app_identity.clone()),
            false,
            &mut state,
            &state_path,
            |_| Ok(()),
            |_, _| {
                executed.set(executed.get() + 1);
                Ok(())
            },
        );
        assert!(replay_response.ok);
        let replay: OperationReceipt =
            serde_json::from_value(replay_response.snapshot.expect("replay receipt snapshot"))
                .expect("decode replay receipt");
        assert_eq!(replay, receipt);
        assert_eq!(executed.get(), 1);
        let status_response = handle(
            Request {
                v: PROTOCOL_VERSION,
                id: "wire-status".to_string(),
                op: "operation_status".to_string(),
                repo: String::new(),
                module: None,
                yaml: Some(
                    serde_json::to_string(&OperationStatusRequest {
                        protocol_version: PROTOCOL_VERSION,
                        operation_id: operation.operation_id.clone(),
                    })
                    .expect("serialize status request"),
                ),
            },
            Some(app_identity),
            false,
            &mut state,
            &state_path,
        );
        assert!(status_response.ok);
        let status: OperationReceipt =
            serde_json::from_value(status_response.snapshot.expect("status receipt snapshot"))
                .expect("decode status receipt");
        assert_eq!(status, receipt);
    }

    #[test]
    fn console_listener_rebinds_when_the_active_user_changes() {
        let directory = tempfile::tempdir().expect("create isolated socket directory");
        let first_uid = unsafe { libc::geteuid() };
        let second_uid = if first_uid == 65_535 {
            65_534
        } else {
            first_uid + 1
        };
        let mut active = None;
        replace_console_listener(&mut active, directory.path(), first_uid, |_, _| Ok(()))
            .expect("bind initial console-user socket");
        let first_path = active.as_ref().expect("initial listener").path.clone();
        assert!(first_path.exists());

        replace_console_listener(&mut active, directory.path(), second_uid, |_, _| Ok(()))
            .expect("replace socket after user transition");
        let listener = active.as_ref().expect("replacement listener");
        assert_eq!(listener.uid, second_uid);
        assert!(!first_path.exists());
        assert!(listener.path.exists());
        let _client = UnixStream::connect(&listener.path).expect("connect to new user socket");
        let _accepted = listener
            .listener
            .accept()
            .expect("accept from new user socket");
    }

    #[test]
    fn accepted_console_stream_reads_delayed_fragmented_requests() {
        let directory = tempfile::tempdir().expect("create isolated socket directory");
        let expected_uid = unsafe { libc::geteuid() };
        let listener = bind_console_listener(directory.path(), expected_uid, |_, _| Ok(()))
            .expect("bind isolated console-user socket");
        let mut client = UnixStream::connect(&listener.path).expect("connect isolated client");
        let (accepted, _) = listener.listener.accept().expect("accept isolated client");
        configure_accepted_stream(&accepted).expect("configure accepted client stream");

        let request = format!(
            r#"{{"v":{},"id":"delayed-fragmented","op":"framing"}}"#,
            PROTOCOL_VERSION
        );
        let split = request.len() / 2;
        let first = request[..split].to_string();
        let second = format!("{}\n", &request[split..]);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            ready_tx.send(()).expect("signal delayed writer startup");
            std::thread::sleep(Duration::from_millis(75));
            client.write_all(first.as_bytes())?;
            std::thread::sleep(Duration::from_millis(75));
            client.write_all(second.as_bytes())?;
            Ok(())
        });
        ready_rx.recv().expect("wait for delayed writer startup");

        let received = read_request(&accepted, expected_uid);
        writer
            .join()
            .expect("request writer thread should not panic")
            .expect("write request fragments");
        let (request, _, _) = received.expect("read delayed fragmented request");
        assert_eq!(request.id, "delayed-fragmented");
        assert!(!operation_requires_peer_identity(&request.op));
    }

    #[test]
    fn startup_without_a_logged_in_user_binds_the_root_socket() {
        let directory = tempfile::tempdir().expect("create isolated socket directory");
        assert_eq!(
            parse_console_uid("0\n").expect("parse pre-login console UID"),
            0
        );
        let listener = bind_console_listener(directory.path(), 0, |_, _| Ok(()))
            .expect("bind root-only endpoint before login");
        assert_eq!(listener.uid, 0);
        assert_eq!(listener.path, socket_path(directory.path(), 0));
        assert_eq!(
            fs::metadata(&listener.path)
                .expect("read isolated socket permissions")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(listener.listener);
        fs::remove_file(listener.path).expect("remove isolated pre-login socket");
    }

    #[test]
    fn revocation_is_durable_before_new_work_is_rejected() {
        let identity = identity();
        let mut state = paired_state(true);
        state
            .unpair_with(&identity, |_| Ok(()))
            .expect("revoke pairing");
        assert!(state.require_pairing(&identity).is_err());
        assert!(!state.pairings[&identity.bundle_identifier].active);
    }

    #[test]
    fn capabilities_expose_only_the_typed_wifi_operation() {
        let response = handle(
            Request {
                v: PROTOCOL_VERSION,
                id: "capabilities".to_string(),
                op: "capabilities".to_string(),
                repo: String::new(),
                module: None,
                yaml: None,
            },
            Some(identity()),
            false,
            &mut State::default(),
            Path::new("unused"),
        );
        assert!(response.ok);
        let report: CapabilityReport =
            serde_json::from_value(response.snapshot.unwrap()).expect("decode capability report");
        assert_eq!(report.capabilities, vec![Capability::WifiNetworkChange]);
    }

    #[test]
    fn direct_cpu_identity_cannot_submit_wifi_operations_even_after_pairing() {
        let identity = Identity {
            team_identifier: "TEAM123456".into(),
            bundle_identifier: "com.astronlab.macmodules.mcpu".into(),
        };
        let mut state = State::default();
        state
            .authorize_pairing_with(&identity, |_| Ok(()))
            .expect("approve direct module identity");
        state
            .pair_with(
                &identity,
                PairingRequest {
                    bundle_identifier: identity.bundle_identifier.clone(),
                    protocol_version: PROTOCOL_VERSION,
                },
                |_| Ok(()),
            )
            .expect("pair direct module identity");
        let request = OperationRequest {
            protocol_version: PROTOCOL_VERSION,
            operation_id: scriptd_bridge_protocol::OperationId::new("cpu-wifi-test")
                .expect("valid operation ID"),
            operation: Operation::SetWifiNetwork {
                ssid: "Test Wi-Fi".into(),
            },
        };
        assert!(state
            .submit_with(&identity, request, |_| Ok(()), |_, _| Ok(()))
            .is_err());
    }

    #[test]
    fn store_module_identity_cannot_obtain_helper_pairing_or_privileged_grants() {
        let identity = Identity {
            team_identifier: "TEAM123456".into(),
            bundle_identifier: "com.astronlab.macmodules.mbrew.store".into(),
        };
        let mut state = State::default();
        assert!(state.authorize_pairing_with(&identity, |_| Ok(())).is_err());
        assert!(state
            .pair_with(
                &identity,
                PairingRequest {
                    bundle_identifier: identity.bundle_identifier.clone(),
                    protocol_version: PROTOCOL_VERSION,
                },
                |_| Ok(()),
            )
            .is_err());
    }

    #[test]
    fn helper_capabilities_are_bound_to_exact_direct_module_identities() {
        for id in [
            "com.astronlab.macmodules.mbrew",
            "com.astronlab.macmodules.mcpu",
            "com.astronlab.macmodules.mwifi",
            "com.astronlab.macmodules.miwatch",
        ] {
            assert!(is_direct_distribution_identity(id), "direct identity {id}");
            assert!(!is_direct_distribution_identity(&format!("{id}.store")));
        }
        assert!(allows_installer_capability(
            "com.astronlab.macmodules.mbrew"
        ));
        assert!(!allows_installer_capability(
            "com.astronlab.macmodules.mwifi"
        ));
        assert!(!allows_installer_capability(
            "com.astronlab.macmodules.mbrew.store"
        ));
        assert!(allows_wifi_capability("com.astronlab.macmodules.mwifi"));
        assert!(!allows_wifi_capability("com.astronlab.macmodules.mcpu"));
        assert!(!allows_wifi_capability(
            "com.astronlab.macmodules.mwifi.store"
        ));
    }

    #[test]
    fn embedded_profiles_accept_only_their_owning_application() {
        let brew = HelperProfile::Brew;
        assert!(brew.accepts_bundle("com.astronlab.macmodules.mbrew"));
        assert!(!brew.accepts_bundle("com.astronlab.macmodules.mwifi"));
        assert!(!brew.accepts_bundle(DIRECT_APP_BUNDLE_IDENTIFIER));

        let wifi = HelperProfile::Wifi;
        assert!(wifi.accepts_bundle("com.astronlab.macmodules.mwifi"));
        assert!(!wifi.accepts_bundle("com.astronlab.macmodules.mbrew"));
        assert!(!wifi.accepts_bundle(DIRECT_APP_BUNDLE_IDENTIFIER));

        let all_in_one = HelperProfile::AllInOne;
        assert!(all_in_one.accepts_bundle(DIRECT_APP_BUNDLE_IDENTIFIER));
        assert!(!all_in_one.accepts_bundle("com.astronlab.macmodules.mbrew"));
        assert!(!all_in_one.accepts_bundle("com.astronlab.macmodules.mwifi"));
    }

    #[test]
    fn capabilities_require_a_signed_peer_on_every_protocol_version() {
        assert!(operation_requires_peer_identity("capabilities"));
        assert!(operation_requires_peer_identity("operation"));
        assert!(!operation_requires_peer_identity("framing"));
    }

    #[test]
    fn embedded_profile_pairing_is_active_without_manual_state() {
        let app = identity();
        let empty = State::default();
        assert!(!pairing_is_active(None, &app, &empty));
        assert!(pairing_is_active(
            Some(HelperProfile::AllInOne),
            &app,
            &empty
        ));
        assert!(!pairing_is_active(Some(HelperProfile::Brew), &app, &empty));
        let wifi = Identity {
            team_identifier: app.team_identifier.clone(),
            bundle_identifier: "com.astronlab.macmodules.mwifi".into(),
        };
        assert!(pairing_is_active(Some(HelperProfile::Wifi), &wifi, &empty));
        assert!(!pairing_is_active(
            Some(HelperProfile::AllInOne),
            &wifi,
            &empty
        ));
        let manual = paired_state(false);
        assert!(
            !pairing_is_active(None, &app, &manual),
            "a revoked legacy pairing stays inactive"
        );
        assert!(
            pairing_is_active(Some(HelperProfile::AllInOne), &app, &manual),
            "an embedded profile is paired by its signed bundle, not manual state"
        );
    }

    #[test]
    fn installer_capability_is_reported_only_to_the_direct_bundle_identity() {
        let mut direct = identity();
        direct.bundle_identifier = DIRECT_APP_BUNDLE_IDENTIFIER.into();
        let direct_report = handle(
            Request {
                v: INSTALLER_PROTOCOL_VERSION,
                id: "caps-direct".into(),
                op: "capabilities".into(),
                repo: String::new(),
                module: None,
                yaml: None,
            },
            Some(direct),
            false,
            &mut State::default(),
            Path::new("unused"),
        );
        assert_eq!(direct_report.v, INSTALLER_PROTOCOL_VERSION);
        let direct_report: CapabilityReport =
            serde_json::from_value(direct_report.snapshot.unwrap()).unwrap();
        assert!(direct_report.offers(Capability::InstallerPackageV1));

        let store_report = handle(
            Request {
                v: INSTALLER_PROTOCOL_VERSION,
                id: "caps-store".into(),
                op: "capabilities".into(),
                repo: String::new(),
                module: None,
                yaml: None,
            },
            Some(Identity {
                team_identifier: "TEAM123456".into(),
                bundle_identifier: "com.astronlab.scriptd.appstore".into(),
            }),
            false,
            &mut State::default(),
            Path::new("unused"),
        );
        let store_report: CapabilityReport =
            serde_json::from_value(store_report.snapshot.unwrap()).unwrap();
        assert!(!store_report.offers(Capability::InstallerPackageV1));
    }

    #[test]
    fn app_store_receipt_blocks_bridge_authentication_for_same_bundle_identifier() {
        let bundle = tempfile::tempdir().expect("create app bundle fixture");
        let app = bundle.path().join("Scriptd.app");
        let executable = app.join("Contents/MacOS/scriptd");
        let receipt = app.join("Contents/_MASReceipt/receipt");
        std::fs::create_dir_all(executable.parent().expect("executable parent"))
            .expect("create executable path");
        std::fs::write(&executable, b"fixture").expect("write executable fixture");
        assert!(!has_mas_receipt(&executable));
        std::fs::create_dir_all(receipt.parent().expect("receipt parent"))
            .expect("create receipt path");
        std::fs::write(&receipt, b"store receipt").expect("write receipt fixture");
        assert!(has_mas_receipt(&executable));
    }

    #[test]
    fn code_signature_queries_bind_to_the_running_peer_pid() {
        assert_eq!(process_code_reference(42), "+42");
    }

    #[test]
    fn bridge_peer_requirement_accepts_only_the_developer_id_certificate_class() {
        let requirement =
            developer_id_requirement("TEAM123456", DIRECT_APP_BUNDLE_IDENTIFIER).unwrap();
        assert!(requirement.starts_with("=anchor apple generic and "));
        assert!(requirement.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"));
        assert!(requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
        assert!(requirement.contains("certificate leaf[subject.OU] = \"TEAM123456\""));
        assert!(!requirement.contains("100.6.1.9"));
        assert!(developer_id_requirement("bad-team!", DIRECT_APP_BUNDLE_IDENTIFIER).is_err());
    }

    #[test]
    fn v4_package_approval_queries_are_paired_and_scoped_to_the_authenticated_app() {
        let identity = Identity {
            team_identifier: "TEAM123456".into(),
            bundle_identifier: DIRECT_APP_BUNDLE_IDENTIFIER.into(),
        };
        let grant = InstallerGrant {
            app_identity: identity.clone(),
            publisher_team_identifier: "VENDOR1234".into(),
            package_identifier: "com.vendor.app".into(),
            method: "package_installer_v1".into(),
        };
        let mut state = State {
            pairings: BTreeMap::from([(
                identity.bundle_identifier.clone(),
                Pairing {
                    team_identifier: identity.team_identifier.clone(),
                    bundle_identifier: identity.bundle_identifier.clone(),
                    active: true,
                },
            )]),
            installer_grants: BTreeMap::from([(
                installer_grant_key(&identity, &grant.package_identifier),
                grant,
            )]),
            ..State::default()
        };
        let status = handle(
            Request {
                v: INSTALLER_PROTOCOL_VERSION,
                id: "package-status".into(),
                op: "package_approval_status".into(),
                repo: String::new(),
                module: None,
                yaml: Some(
                    serde_json::to_string(&InstallerApprovalQuery {
                        publisher_team_identifier: "VENDOR1234".into(),
                        package_identifier: "com.vendor.app".into(),
                    })
                    .unwrap(),
                ),
            },
            Some(identity.clone()),
            false,
            &mut state,
            Path::new("unused"),
        );
        assert!(status.ok);
        assert_eq!(status.snapshot.unwrap()["approved"], true);

        let publisher_mismatch = handle(
            Request {
                v: INSTALLER_PROTOCOL_VERSION,
                id: "package-status-mismatch".into(),
                op: "package_approval_status".into(),
                repo: String::new(),
                module: None,
                yaml: Some(
                    serde_json::json!({
                        "publisher_team_identifier": "OTHERTEAM1",
                        "package_identifier": "com.vendor.app",
                    })
                    .to_string(),
                ),
            },
            Some(identity.clone()),
            false,
            &mut state,
            Path::new("unused"),
        );
        assert!(publisher_mismatch.ok);
        assert_eq!(publisher_mismatch.snapshot.unwrap()["approved"], false);

        let list = handle(
            Request {
                v: INSTALLER_PROTOCOL_VERSION,
                id: "package-list".into(),
                op: "package_approval_list".into(),
                repo: String::new(),
                module: None,
                yaml: None,
            },
            Some(identity),
            false,
            &mut state,
            Path::new("unused"),
        );
        assert!(list.ok);
        let approvals = list.snapshot.unwrap();
        assert_eq!(approvals.as_array().unwrap().len(), 1);
        assert_eq!(approvals[0]["package_identifier"], "com.vendor.app");
    }

    #[test]
    fn package_install_requires_a_separate_publisher_grant() {
        let identity = identity();
        let request = OperationRequest {
            protocol_version: INSTALLER_PROTOCOL_VERSION,
            operation_id: scriptd_bridge_protocol::OperationId::new("brew-pkg-1")
                .expect("valid operation id"),
            operation: Operation::InstallApprovedPackage {
                package_identifier: "com.vendor.product".into(),
                package_path: "/Users/test/Downloads/product.pkg".into(),
            },
        };
        let mut state = paired_state(true);
        let executed = std::cell::Cell::new(false);
        let result = state.submit_with(
            &identity,
            request,
            |_| Ok(()),
            |_, _| {
                executed.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!executed.get(), "an unapproved installer must never run");
    }

    #[test]
    fn package_approval_does_not_create_or_change_wifi_pairing() {
        let identity = identity();
        let grant = InstallerGrant {
            app_identity: identity.clone(),
            publisher_team_identifier: "VENDOR1234".into(),
            package_identifier: "com.vendor.product".into(),
            method: "package_installer_v1".into(),
        };
        let mut state = State::default();
        let key = installer_grant_key(&identity, &grant.package_identifier);
        state.installer_grants.insert(key, grant);
        assert!(state.require_pairing(&identity).is_err());
        assert!(state
            .installer_grant(&identity, "com.vendor.product")
            .is_ok());
        assert!(state
            .installer_grant(&identity, "com.vendor.other")
            .is_err());
    }

    #[test]
    fn installer_grant_revocation_rolls_back_if_persistence_fails() {
        let mut app_identity = identity();
        app_identity.bundle_identifier = DIRECT_APP_BUNDLE_IDENTIFIER.into();
        let grant = InstallerGrant {
            app_identity: app_identity.clone(),
            publisher_team_identifier: "VENDOR1234".into(),
            package_identifier: "com.vendor.product".into(),
            method: "package_installer_v1".into(),
        };
        let mut state = State::default();
        state
            .set_installer_grant_with(grant.clone(), false, |_| Ok(()))
            .expect("save an approval");
        assert!(state
            .set_installer_grant_with(grant.clone(), true, |_| {
                bail!("simulated persistence error")
            })
            .is_err());
        assert!(state
            .installer_grant(&app_identity, &grant.package_identifier)
            .is_ok());
        state
            .set_installer_grant_with(grant.clone(), true, |_| Ok(()))
            .expect("revoke future authorization");
        assert!(state
            .installer_grant(&app_identity, &grant.package_identifier)
            .is_err());
    }

    #[test]
    fn developer_id_publisher_parser_extracts_only_a_valid_team_identifier() {
        assert_eq!(
            installer::developer_id_team(
                "1. Developer ID Installer: Vendor (VENDOR1234)\nExpires: 2027-01-01"
            ),
            Some("VENDOR1234")
        );
        assert_eq!(
            installer::developer_id_team("origin=Developer ID Application: Vendor (VENDOR1234)"),
            None
        );
        assert_eq!(
            installer::developer_id_team("origin=Developer ID Installer: Vendor (bad-team!)"),
            None
        );
    }

    #[test]
    fn duplicate_operation_ids_never_execute_the_privileged_action_twice() {
        let identity = identity();
        let request = operation_request("wifi-once");
        let mut state = paired_state(true);
        let executions = std::cell::Cell::new(0);
        let persist = |_: &State| Ok(());
        let first = state
            .submit_with(&identity, request.clone(), persist, |_, _| {
                executions.set(executions.get() + 1);
                Ok(())
            })
            .expect("first operation");
        let second = state
            .submit_with(
                &identity,
                request,
                |_: &State| Ok(()),
                |_, _| {
                    executions.set(executions.get() + 1);
                    Ok(())
                },
            )
            .expect("same operation ID returns its existing receipt");
        assert_eq!(executions.get(), 1);
        assert_eq!(first, second);
        assert_eq!(first.state, OperationState::Succeeded);
    }

    #[test]
    fn revocation_blocks_new_operations_but_keeps_old_receipts_readable() {
        let identity = identity();
        let request = operation_request("wifi-accepted");
        let mut state = paired_state(false);
        let receipt = OperationReceipt {
            protocol_version: PROTOCOL_VERSION,
            operation_id: request.operation_id.clone(),
            state: OperationState::Unknown,
            message: Some("reconcile only".to_string()),
        };
        state.operations.insert(
            request.operation_id.as_str().to_string(),
            OperationRecord {
                identity: identity.clone(),
                request: request.clone(),
                receipt: receipt.clone(),
            },
        );
        assert!(state
            .submit_with(
                &identity,
                operation_request("wifi-new"),
                |_: &State| Ok(()),
                |_, _| Ok(())
            )
            .is_err());
        let reconciled = state
            .status(
                &identity,
                OperationStatusRequest {
                    protocol_version: PROTOCOL_VERSION,
                    operation_id: request.operation_id,
                },
            )
            .expect("existing operation remains readable");
        assert_eq!(reconciled, receipt);
    }

    #[test]
    fn restart_marks_in_flight_receipts_unknown_without_replay() {
        let identity = identity();
        let request = operation_request("wifi-interrupted");
        let mut state = paired_state(true);
        state.operations.insert(
            request.operation_id.as_str().to_string(),
            OperationRecord {
                identity: identity.clone(),
                request: request.clone(),
                receipt: OperationReceipt {
                    protocol_version: PROTOCOL_VERSION,
                    operation_id: request.operation_id.clone(),
                    state: OperationState::Running,
                    message: None,
                },
            },
        );
        state.mark_interrupted_unknown();
        let receipt = state
            .status(
                &identity,
                OperationStatusRequest {
                    protocol_version: PROTOCOL_VERSION,
                    operation_id: request.operation_id,
                },
            )
            .expect("unknown operation remains reconcilable");
        assert_eq!(receipt.state, OperationState::Unknown);
        assert!(receipt.message.unwrap().contains("not replayed"));
    }

    #[test]
    fn protocol_version_mismatch_is_rejected_before_dispatch() {
        let response = handle(
            Request {
                v: PROTOCOL_VERSION - 1,
                id: "old-client".to_string(),
                op: "capabilities".to_string(),
                repo: String::new(),
                module: None,
                yaml: None,
            },
            None,
            false,
            &mut State::default(),
            Path::new("unused"),
        );
        assert!(!response.ok);
        assert!(response.message.unwrap().contains("unsupported"));
    }
    #[test]
    fn user_callable_pairing_approval_is_rejected_without_creating_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = State::default();
        let response = handle(
            Request {
                v: PROTOCOL_VERSION,
                id: "no-consent".into(),
                op: "request_authorize_pairing".into(),
                repo: String::new(),
                module: None,
                yaml: None,
            },
            Some(identity()),
            false,
            &mut state,
            &temp.path().join("state.json"),
        );
        assert!(!response.ok);
        assert!(state.pairing_authorizations.is_empty());
        assert!(state.pairings.is_empty());
        assert!(!temp.path().join("state.json").exists());
    }
}
