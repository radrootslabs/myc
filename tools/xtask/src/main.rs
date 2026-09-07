#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    env, fmt, fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tar::{Builder as TarBuilder, Header as TarHeader};
use tempfile::{NamedTempFile, TempDir};

const SERVICE: &str = "myc";
const VERSION: &str = "0.1.0";
const REPOSITORY: &str = "https://github.com/radrootslabs/myc";
const RUST_VERSION: &str = "1.97.1";
const HOST_FEATURE_PROFILE: &str = "service-host";
const SOURCE_LOCK: &str = "radroots.service.source-lock.v3.toml";
const CONFIG_EXAMPLE: &str = "contracts/services_hardening/config.v1.example.toml";
const CONFIG_SCHEMA: &str = "contracts/services_hardening/config.v1.schema.json";
const SYSTEMD_UNIT: &str = "packaging/systemd/myc@.service";
const SUPPORTED_TARGETS: [&str; 2] = ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"];
const OUTPUT_NAMES: [&str; 12] = [
    "LICENSE",
    "SHA256SUMS",
    "THIRD-PARTY-NOTICES.txt",
    "artifact-manifest.v1.json",
    "binary.tar.gz",
    "config.example.toml",
    "config.schema.json",
    "provenance-input.v1.json",
    SOURCE_LOCK,
    "sbom.cdx.json",
    "service-source.tar.gz",
    "systemd.service",
];
const MAX_TEXT_BYTES: u64 = 1_048_576;
const MAX_DOCUMENT_BYTES: u64 = 16_777_216;
const MAX_METADATA_BYTES: u64 = 33_554_432;
const MAX_BINARY_BYTES: u64 = 536_870_912;
const MAX_SOURCE_ARCHIVE_BYTES: u64 = 1_073_741_824;
const MAX_TRACKED_FILES: usize = 4_096;
const MAX_PACKAGES: usize = 8_192;
const COPY_BUFFER_BYTES: usize = 65_536;
const SECRET_PATTERNS: [&[u8]; 7] = [
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"github_pat_",
    b"ghp_",
    b"xoxb-",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Check,
    Write,
}

#[derive(Debug)]
struct NativeReleaseArgs {
    mode: Mode,
    target: String,
    binary: PathBuf,
    output: PathBuf,
    source_date_epoch: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseError {
    InvalidArguments,
    InvalidSource,
    DirtySource,
    InvalidBinary,
    InvalidOutput,
    InvalidMetadata,
    InvalidSourceLock,
    ProtectedMaterial,
    StaleOutput,
    Generation,
}

impl ReleaseError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::InvalidSource => "invalid_source",
            Self::DirtySource => "dirty_source",
            Self::InvalidBinary => "invalid_binary",
            Self::InvalidOutput => "invalid_output",
            Self::InvalidMetadata => "invalid_metadata",
            Self::InvalidSourceLock => "invalid_source_lock",
            Self::ProtectedMaterial => "protected_material_detected",
            Self::StaleOutput => "stale_output",
            Self::Generation => "generation_failure",
        }
    }
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArguments => "native release arguments are invalid",
            Self::InvalidSource => "native release source is invalid",
            Self::DirtySource => "native release source is not an exact clean revision",
            Self::InvalidBinary => "native release binary is invalid",
            Self::InvalidOutput => "native release output is invalid",
            Self::InvalidMetadata => "native release metadata is invalid",
            Self::InvalidSourceLock => "native release source lock is invalid",
            Self::ProtectedMaterial => "native release input contains protected material",
            Self::StaleOutput => "native release artifact set is absent or stale",
            Self::Generation => "native release artifacts could not be generated",
        })
    }
}

impl std::error::Error for ReleaseError {}

#[derive(Clone, Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    resolve: Option<CargoResolve>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    license: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoNode>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoNode {
    id: String,
    dependencies: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceLock {
    schema: String,
    contract_version: u32,
    service: String,
    repository: String,
    revision: String,
    architecture: String,
    workspace_catalog_sha256: String,
    version: String,
    source_archive_sha256: String,
    source_archive_contract: SourceArchiveContract,
    cargo_lock_sha256: String,
    rust_version: String,
    host_feature_profile: String,
    nix: NixEvidence,
    artifact_contract: ArtifactContract,
    sqlite: SqliteContract,
    contract_versions: ContractVersions,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NixEvidence {
    material: String,
    lib_revision: String,
    public_input_lock: PublicInputLock,
    parent_result: ParentResult,
    supported_systems: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInputLock {
    path: String,
    sha256: String,
    binding: String,
    mutable_reference: String,
    lib_input: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentResult {
    embedded_in_public_input_lock: bool,
    embedded_in_source_lock: bool,
    storage: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceArchiveContract {
    binding: String,
    format: String,
    compression: String,
    compression_timestamp: String,
    entry_order: String,
    path_prefix: String,
    file_mode: String,
    uid: u32,
    gid: u32,
    uname: String,
    gname: String,
    mtime: String,
    pax_headers: String,
    directory_entries: String,
    symlinks: String,
    hardlinks: String,
    submodules: String,
    trailer: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactContract {
    path: String,
    sha256: String,
    binding: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SqliteContract {
    high_level_authority: String,
    second_pool_connection_query_transaction_migration_authority: String,
    incremental_backup_adapter: String,
    native_linkage_count: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContractVersions {
    config: u32,
    state: u32,
    admin: u32,
    status: u32,
    provider: u32,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ArtifactRecord {
    path: String,
    byte_length: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ArtifactManifest {
    schema: &'static str,
    contract_version: u32,
    service: &'static str,
    version: &'static str,
    target: String,
    source_date_epoch: u32,
    service_repository: &'static str,
    service_revision: String,
    lib_repository: String,
    lib_revision: String,
    rust_version: &'static str,
    host_feature_profile: &'static str,
    contract_versions: ContractVersions,
    protected_material_included: bool,
    nix_qualified: bool,
    oci_included: bool,
    artifacts: Vec<ArtifactRecord>,
}

#[derive(Debug, Serialize)]
struct ProvenanceInput {
    schema: &'static str,
    contract_version: u32,
    predicate_type: &'static str,
    build_type: &'static str,
    builder_id: &'static str,
    service: &'static str,
    version: &'static str,
    target: String,
    source_date_epoch: u32,
    service_repository: &'static str,
    service_revision: String,
    lib_repository: String,
    lib_revision: String,
    source_lock_sha256: String,
    manifest_sha256: String,
    subjects: Vec<ArtifactRecord>,
    signing_required: bool,
    signed: bool,
}

#[derive(Debug, Serialize)]
struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    version: u32,
    metadata: SbomMetadata,
    components: Vec<SbomComponent>,
    dependencies: Vec<SbomDependency>,
}

#[derive(Debug, Serialize)]
struct SbomMetadata {
    component: SbomRootComponent,
}

#[derive(Debug, Serialize)]
struct SbomRootComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct SbomComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<SbomLicenseChoice>>,
    properties: Vec<SbomProperty>,
}

#[derive(Debug, Serialize)]
struct SbomLicenseChoice {
    expression: String,
}

#[derive(Debug, Serialize)]
struct SbomProperty {
    name: &'static str,
    value: String,
}

#[derive(Debug, Serialize)]
struct SbomDependency {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(rename = "dependsOn")]
    depends_on: Vec<String>,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{}: {}", error.code(), error);
        std::process::exit(1);
    }
}

fn run_main() -> Result<(), ReleaseError> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("native-release") => {
            let args = parse_native_release_args(arguments.collect())?;
            native_release(&workspace_root(), &args)
        }
        _ => Err(ReleaseError::InvalidArguments),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask is nested at tools/xtask")
        .to_path_buf()
}

fn parse_native_release_args(values: Vec<String>) -> Result<NativeReleaseArgs, ReleaseError> {
    let mut mode = None;
    let mut target = None;
    let mut binary = None;
    let mut output = None;
    let mut source_date_epoch = None;
    let mut index = 0;
    while index < values.len() {
        let value = values
            .get(index + 1)
            .ok_or(ReleaseError::InvalidArguments)?;
        match values[index].as_str() {
            "--mode" => {
                let parsed = match value.as_str() {
                    "check" => Mode::Check,
                    "write" => Mode::Write,
                    _ => return Err(ReleaseError::InvalidArguments),
                };
                if mode.replace(parsed).is_some() {
                    return Err(ReleaseError::InvalidArguments);
                }
            }
            "--target" => {
                if target.replace(value.clone()).is_some() {
                    return Err(ReleaseError::InvalidArguments);
                }
            }
            "--binary" => {
                if binary.replace(PathBuf::from(value)).is_some() {
                    return Err(ReleaseError::InvalidArguments);
                }
            }
            "--output" => {
                if output.replace(PathBuf::from(value)).is_some() {
                    return Err(ReleaseError::InvalidArguments);
                }
            }
            "--source-date-epoch" => {
                let parsed = value
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or(ReleaseError::InvalidArguments)?;
                if source_date_epoch.replace(parsed).is_some() {
                    return Err(ReleaseError::InvalidArguments);
                }
            }
            _ => return Err(ReleaseError::InvalidArguments),
        }
        index += 2;
    }
    let args = NativeReleaseArgs {
        mode: mode.ok_or(ReleaseError::InvalidArguments)?,
        target: target.ok_or(ReleaseError::InvalidArguments)?,
        binary: binary.ok_or(ReleaseError::InvalidArguments)?,
        output: output.ok_or(ReleaseError::InvalidArguments)?,
        source_date_epoch: source_date_epoch.ok_or(ReleaseError::InvalidArguments)?,
    };
    if !SUPPORTED_TARGETS.contains(&args.target.as_str())
        || !args.binary.is_absolute()
        || !args.output.is_absolute()
    {
        return Err(ReleaseError::InvalidArguments);
    }
    Ok(args)
}

fn native_release(root: &Path, args: &NativeReleaseArgs) -> Result<(), ReleaseError> {
    validate_source_root(root)?;
    validate_clean_source(root)?;
    let initial_head = git_capture(root, &["rev-parse", "HEAD"], 128)?;
    let initial_head = exact_line(&initial_head).ok_or(ReleaseError::InvalidSource)?;
    if !lower_hex(initial_head, 40) {
        return Err(ReleaseError::InvalidSource);
    }
    validate_binary(&args.binary, &args.target)?;
    validate_output_path(root, &args.output)?;
    let source_lock = read_source_lock(root)?;
    let metadata = cargo_metadata(root)?;
    validate_metadata(&metadata)?;

    let parent = args.output.parent().ok_or(ReleaseError::InvalidOutput)?;
    let staging = tempfile::Builder::new()
        .prefix(".myc-native-release-")
        .tempdir_in(parent)
        .map_err(|_| ReleaseError::Generation)?;
    let stage = staging.path();
    set_directory_permissions(stage)?;

    copy_bounded(
        &root.join("LICENSE"),
        &stage.join("LICENSE"),
        MAX_TEXT_BYTES,
    )?;
    copy_bounded(
        &root.join(CONFIG_EXAMPLE),
        &stage.join("config.example.toml"),
        MAX_TEXT_BYTES,
    )?;
    copy_bounded(
        &root.join(CONFIG_SCHEMA),
        &stage.join("config.schema.json"),
        MAX_TEXT_BYTES,
    )?;
    copy_bounded(
        &root.join(SYSTEMD_UNIT),
        &stage.join("systemd.service"),
        MAX_TEXT_BYTES,
    )?;
    copy_bounded(
        &root.join(SOURCE_LOCK),
        &stage.join(SOURCE_LOCK),
        MAX_TEXT_BYTES,
    )?;
    create_binary_archive(
        &args.binary,
        &stage.join("binary.tar.gz"),
        &args.target,
        args.source_date_epoch,
    )?;
    create_source_archive(
        root,
        &stage.join("service-source.tar.gz"),
        args.source_date_epoch,
    )?;
    let (sbom, notices) = supply_chain_documents(&metadata)?;
    write_json(&stage.join("sbom.cdx.json"), &sbom)?;
    write_generated(&stage.join("THIRD-PARTY-NOTICES.txt"), notices.as_bytes())?;

    let source_lock_sha256 = hash_regular(&stage.join(SOURCE_LOCK), MAX_TEXT_BYTES)?.sha256;
    let payload = inventory_records(stage)?;
    let manifest = ArtifactManifest {
        schema: "radroots.service.release-artifacts.v1",
        contract_version: 1,
        service: SERVICE,
        version: VERSION,
        target: args.target.clone(),
        source_date_epoch: args.source_date_epoch,
        service_repository: REPOSITORY,
        service_revision: initial_head.to_owned(),
        lib_repository: source_lock.repository.clone(),
        lib_revision: source_lock.revision.clone(),
        rust_version: RUST_VERSION,
        host_feature_profile: HOST_FEATURE_PROFILE,
        contract_versions: source_lock.contract_versions.clone(),
        protected_material_included: false,
        nix_qualified: true,
        oci_included: false,
        artifacts: payload,
    };
    write_json(&stage.join("artifact-manifest.v1.json"), &manifest)?;
    let manifest_sha256 =
        hash_regular(&stage.join("artifact-manifest.v1.json"), MAX_DOCUMENT_BYTES)?.sha256;
    let provenance = ProvenanceInput {
        schema: "radroots.service.provenance-input.v1",
        contract_version: 1,
        predicate_type: "https://slsa.dev/provenance/v1",
        build_type: "https://radroots.dev/contracts/myc-native-release/v2",
        builder_id: "https://radroots.dev/builders/myc-native-release/v2",
        service: SERVICE,
        version: VERSION,
        target: args.target.clone(),
        source_date_epoch: args.source_date_epoch,
        service_repository: REPOSITORY,
        service_revision: initial_head.to_owned(),
        lib_repository: source_lock.repository,
        lib_revision: source_lock.revision,
        source_lock_sha256,
        manifest_sha256,
        subjects: inventory_records(stage)?,
        signing_required: true,
        signed: false,
    };
    write_json(&stage.join("provenance-input.v1.json"), &provenance)?;
    write_checksums(stage)?;
    validate_exact_inventory(stage)?;
    let expected = inventory_records(stage)?;

    validate_clean_source(root)?;
    if exact_line(&git_capture(root, &["rev-parse", "HEAD"], 128)?) != Some(initial_head) {
        return Err(ReleaseError::DirtySource);
    }

    if args.output.exists() {
        compare_output(&args.output, &expected)?;
        sync_directory(&args.output)?;
        sync_directory(parent)?;
        return Ok(());
    }
    if args.mode == Mode::Check {
        return Err(ReleaseError::StaleOutput);
    }
    sync_directory(stage)?;
    publish_directory(stage, &args.output)?;
    sync_directory(parent)?;
    compare_output(&args.output, &expected)
}

fn validate_source_root(root: &Path) -> Result<(), ReleaseError> {
    if !root.is_absolute()
        || fs::symlink_metadata(root)
            .map(|metadata| metadata.file_type().is_symlink() || !metadata.is_dir())
            .unwrap_or(true)
        || root.join("docs").exists()
        || root.join(".github").exists()
        || root.join(".act").exists()
    {
        return Err(ReleaseError::InvalidSource);
    }
    for required in [
        "Cargo.toml",
        "Cargo.lock",
        "LICENSE",
        SOURCE_LOCK,
        CONFIG_EXAMPLE,
        CONFIG_SCHEMA,
        SYSTEMD_UNIT,
    ] {
        validate_regular(
            &root.join(required),
            MAX_DOCUMENT_BYTES,
            ReleaseError::InvalidSource,
        )?;
    }
    Ok(())
}

fn validate_clean_source(root: &Path) -> Result<(), ReleaseError> {
    for arguments in [
        &["diff", "--quiet", "--"] as &[&str],
        &["diff", "--cached", "--quiet", "--"],
    ] {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ReleaseError::DirtySource)?;
        if !status.success() {
            return Err(ReleaseError::DirtySource);
        }
    }
    let untracked = command_capture_bounded(
        Command::new("git")
            .args(["ls-files", "--others", "--exclude-standard", "-z"])
            .current_dir(root),
        1,
        ReleaseError::DirtySource,
    )?;
    if !untracked.is_empty() {
        return Err(ReleaseError::DirtySource);
    }
    Ok(())
}

fn validate_binary(path: &Path, target: &str) -> Result<(), ReleaseError> {
    open_binary(path, target).map(|_| ())
}

fn validate_output_path(root: &Path, output: &Path) -> Result<(), ReleaseError> {
    let parent = output.parent().ok_or(ReleaseError::InvalidOutput)?;
    let canonical_root = fs::canonicalize(root).map_err(|_| ReleaseError::InvalidSource)?;
    let canonical_parent = fs::canonicalize(parent).map_err(|_| ReleaseError::InvalidOutput)?;
    if output == Path::new("/")
        || output.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir
                    | std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
            )
        })
        || canonical_parent.starts_with(canonical_root)
        || fs::symlink_metadata(parent)
            .map(|metadata| metadata.file_type().is_symlink() || !metadata.is_dir())
            .unwrap_or(true)
        || output
            .file_name()
            .and_then(|value| value.to_str())
            .is_none_or(|value| value.is_empty() || value == "." || value == "..")
    {
        return Err(ReleaseError::InvalidOutput);
    }
    match fs::symlink_metadata(output) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ReleaseError::InvalidOutput);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ReleaseError::InvalidOutput),
    }
    Ok(())
}

fn read_source_lock(root: &Path) -> Result<SourceLock, ReleaseError> {
    let bytes = read_bounded(
        &root.join(SOURCE_LOCK),
        MAX_TEXT_BYTES,
        ReleaseError::InvalidSourceLock,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ReleaseError::InvalidSourceLock)?;
    let lock: SourceLock = toml::from_str(text).map_err(|_| ReleaseError::InvalidSourceLock)?;
    let cargo_lock = hash_regular(&root.join("Cargo.lock"), MAX_DOCUMENT_BYTES)?;
    let flake_lock = hash_regular(&root.join("flake.lock"), MAX_DOCUMENT_BYTES)?;
    let artifact_contract = hash_regular(
        &root.join("contracts/release/myc-artifact-contract.v3.json"),
        MAX_DOCUMENT_BYTES,
    )?;
    let revisions = cargo_dependency_revisions(root)?;
    if lock.schema != "radroots.service.source-lock.v3"
        || lock.contract_version != 3
        || lock.service != SERVICE
        || lock.repository != "https://github.com/radrootslabs/lib"
        || !lower_hex(&lock.revision, 40)
        || lock.architecture != "radroots.crates.release.v2"
        || !lower_hex(&lock.workspace_catalog_sha256, 64)
        || lock.version != "0.1.0-alpha"
        || !lower_hex(&lock.source_archive_sha256, 64)
        || lock.cargo_lock_sha256 != cargo_lock.sha256
        || lock.rust_version != RUST_VERSION
        || lock.host_feature_profile != HOST_FEATURE_PROFILE
        || lock.source_archive_contract.binding
            != "sha256_of_canonical_exact_lib_revision_tree_archive"
        || lock.source_archive_contract.format != "ustar"
        || lock.source_archive_contract.compression != "none"
        || lock.source_archive_contract.compression_timestamp != "not_applicable"
        || lock.source_archive_contract.entry_order != "bytewise_git_path"
        || lock.source_archive_contract.path_prefix != "none"
        || lock.source_archive_contract.file_mode != "git_index_100644_or_100755"
        || lock.source_archive_contract.uid != 0
        || lock.source_archive_contract.gid != 0
        || !lock.source_archive_contract.uname.is_empty()
        || !lock.source_archive_contract.gname.is_empty()
        || lock.source_archive_contract.mtime != "lib_revision_commit_timestamp"
        || lock.source_archive_contract.pax_headers != "forbidden"
        || lock.source_archive_contract.directory_entries != "omitted"
        || lock.source_archive_contract.symlinks != "forbidden"
        || lock.source_archive_contract.hardlinks != "forbidden"
        || lock.source_archive_contract.submodules != "forbidden"
        || lock.source_archive_contract.trailer != "two_zero_blocks"
        || lock.nix.material != "qualified"
        || lock.nix.lib_revision != lock.revision
        || lock.nix.supported_systems != ["aarch64-darwin", "x86_64-linux"]
        || lock.nix.public_input_lock.path != "flake.lock"
        || lock.nix.public_input_lock.sha256 != flake_lock.sha256
        || lock.nix.public_input_lock.binding != "exact_regular_file_bytes"
        || lock.nix.public_input_lock.mutable_reference != "forbidden"
        || lock.nix.public_input_lock.lib_input != "lib"
        || lock.nix.parent_result.embedded_in_public_input_lock
        || lock.nix.parent_result.embedded_in_source_lock
        || lock.nix.parent_result.storage != "separate_generation_scoped_evidence"
        || lock.artifact_contract.path != "contracts/release/myc-artifact-contract.v3.json"
        || lock.artifact_contract.sha256 != artifact_contract.sha256
        || lock.artifact_contract.binding != "exact_regular_file_bytes_in_same_source_revision"
        || lock.sqlite.high_level_authority != "sqlx_only"
        || lock
            .sqlite
            .second_pool_connection_query_transaction_migration_authority
            != "forbidden"
        || lock.sqlite.incremental_backup_adapter != "sealed_native_sqlx_owned_locked_handle_only"
        || lock.sqlite.native_linkage_count != 1
        || revisions != BTreeSet::from([lock.revision.clone()])
        || [
            lock.contract_versions.config,
            lock.contract_versions.state,
            lock.contract_versions.admin,
            lock.contract_versions.status,
            lock.contract_versions.provider,
        ]
        .contains(&0)
    {
        return Err(ReleaseError::InvalidSourceLock);
    }
    Ok(lock)
}

fn cargo_dependency_revisions(root: &Path) -> Result<BTreeSet<String>, ReleaseError> {
    let bytes = read_bounded(
        &root.join("Cargo.toml"),
        MAX_TEXT_BYTES,
        ReleaseError::InvalidSourceLock,
    )?;
    let value: toml::Value =
        toml::from_str(std::str::from_utf8(&bytes).map_err(|_| ReleaseError::InvalidSourceLock)?)
            .map_err(|_| ReleaseError::InvalidSourceLock)?;
    let dependencies = value
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or(ReleaseError::InvalidSourceLock)?;
    let mut revisions = BTreeSet::new();
    let mut count = 0_usize;
    for (name, dependency) in dependencies {
        if !name.starts_with("radroots_") {
            continue;
        }
        count += 1;
        let table = dependency
            .as_table()
            .ok_or(ReleaseError::InvalidSourceLock)?;
        if table.get("git").and_then(toml::Value::as_str)
            != Some("https://github.com/radrootslabs/lib")
            || table.contains_key("path")
            || table.contains_key("branch")
            || table.contains_key("tag")
        {
            return Err(ReleaseError::InvalidSourceLock);
        }
        revisions.insert(
            table
                .get("rev")
                .and_then(toml::Value::as_str)
                .filter(|revision| lower_hex(revision, 40))
                .ok_or(ReleaseError::InvalidSourceLock)?
                .to_owned(),
        );
    }
    if count != 11 {
        return Err(ReleaseError::InvalidSourceLock);
    }
    Ok(revisions)
}

fn cargo_metadata(root: &Path) -> Result<CargoMetadata, ReleaseError> {
    let bytes = command_capture_bounded(
        Command::new("cargo")
            .args(["metadata", "--format-version", "1", "--locked", "--offline"])
            .current_dir(root),
        MAX_METADATA_BYTES,
        ReleaseError::InvalidMetadata,
    )?;
    serde_json::from_slice(&bytes).map_err(|_| ReleaseError::InvalidMetadata)
}

fn validate_metadata(metadata: &CargoMetadata) -> Result<(), ReleaseError> {
    if metadata.packages.is_empty()
        || metadata.packages.len() > MAX_PACKAGES
        || metadata.workspace_members.len() != 2
        || metadata.resolve.is_none()
        || !metadata
            .packages
            .iter()
            .any(|package| package.name == SERVICE && package.version == VERSION)
    {
        return Err(ReleaseError::InvalidMetadata);
    }
    Ok(())
}

fn create_binary_archive(
    binary: &Path,
    output: &Path,
    target: &str,
    epoch: u32,
) -> Result<(), ReleaseError> {
    let mut input = open_binary(binary, target)?;
    let metadata = input.metadata().map_err(|_| ReleaseError::InvalidBinary)?;
    let file = create_new(output)?;
    let encoder = GzBuilder::new().mtime(epoch).write(
        BoundedWriter::new(file, MAX_BINARY_BYTES + MAX_TEXT_BYTES),
        Compression::best(),
    );
    let mut tar = TarBuilder::new(encoder);
    tar.mode(tar::HeaderMode::Deterministic);
    let mut header = TarHeader::new_gnu();
    header.set_size(metadata.len());
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(u64::from(epoch));
    header.set_cksum();
    tar.append_data(
        &mut header,
        format!("myc-{VERSION}-{target}/myc"),
        &mut input,
    )
    .map_err(|_| ReleaseError::Generation)?;
    let encoder = tar.into_inner().map_err(|_| ReleaseError::Generation)?;
    encoder
        .finish()
        .map_err(|_| ReleaseError::Generation)?
        .sync_all()
        .map_err(|_| ReleaseError::Generation)
}

fn create_source_archive(root: &Path, output: &Path, epoch: u32) -> Result<(), ReleaseError> {
    let work = TempDir::new().map_err(|_| ReleaseError::Generation)?;
    let source = work.path().join(format!("myc-{VERSION}-source"));
    fs::create_dir(&source).map_err(|_| ReleaseError::Generation)?;
    extract_exact_head(root, &source, work.path())?;
    let tracked = count_tree(&source)?;
    if tracked == 0 || tracked > MAX_TRACKED_FILES {
        return Err(ReleaseError::InvalidSource);
    }
    let vendor_config = command_capture_bounded(
        Command::new("cargo")
            .args(["vendor", "--locked", "--versioned-dirs", "vendor"])
            .current_dir(&source),
        MAX_TEXT_BYTES,
        ReleaseError::Generation,
    )?;
    let cargo_config = source.join(".cargo/config.toml");
    let mut config = read_bounded(&cargo_config, MAX_TEXT_BYTES, ReleaseError::Generation)?;
    config.extend_from_slice(b"\n");
    config.extend_from_slice(&vendor_config);
    if config.len() as u64 > MAX_TEXT_BYTES {
        return Err(ReleaseError::Generation);
    }
    fs::write(&cargo_config, &config).map_err(|_| ReleaseError::Generation)?;
    let _ = command_capture_bounded(
        Command::new("cargo")
            .args(["metadata", "--format-version", "1", "--locked", "--offline"])
            .current_dir(&source),
        MAX_METADATA_BYTES,
        ReleaseError::Generation,
    )?;
    create_tree_archive(&source, output, epoch)
}

fn extract_exact_head(root: &Path, destination: &Path, work: &Path) -> Result<(), ReleaseError> {
    let archive = work.join("source-head.tar");
    let archive_file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&archive)
        .map_err(|_| ReleaseError::Generation)?;
    let status = Command::new("git")
        .args(["archive", "--format=tar", "HEAD"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(archive_file))
        .stderr(Stdio::null())
        .status()
        .map_err(|_| ReleaseError::InvalidSource)?;
    if !status.success() {
        return Err(ReleaseError::InvalidSource);
    }
    validate_regular(
        &archive,
        MAX_SOURCE_ARCHIVE_BYTES,
        ReleaseError::InvalidSource,
    )?;
    let file = fs::File::open(archive).map_err(|_| ReleaseError::InvalidSource)?;
    tar::Archive::new(file)
        .unpack(destination)
        .map_err(|_| ReleaseError::InvalidSource)
}

fn count_tree(root: &Path) -> Result<usize, ReleaseError> {
    let mut count = 0_usize;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(directory).map_err(|_| ReleaseError::InvalidSource)?;
        for entry in entries {
            let entry = entry.map_err(|_| ReleaseError::InvalidSource)?;
            let kind = entry.file_type().map_err(|_| ReleaseError::InvalidSource)?;
            if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
                return Err(ReleaseError::InvalidSource);
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else {
                count = count.checked_add(1).ok_or(ReleaseError::InvalidSource)?;
                if count > MAX_TRACKED_FILES {
                    return Err(ReleaseError::InvalidSource);
                }
            }
        }
    }
    Ok(count)
}

#[cfg(unix)]
fn open_binary(path: &Path, target: &str) -> Result<fs::File, ReleaseError> {
    use rustix::fs::{Mode as FileMode, OFlags};
    use std::io::Seek as _;
    use std::os::unix::fs::PermissionsExt as _;

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        FileMode::empty(),
    )
    .map_err(|_| ReleaseError::InvalidBinary)?;
    let mut file = fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|_| ReleaseError::InvalidBinary)?;
    if !metadata.is_file()
        || metadata.len() < 20
        || metadata.len() > MAX_BINARY_BYTES
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(ReleaseError::InvalidBinary);
    }
    let mut header = [0_u8; 20];
    file.read_exact(&mut header)
        .map_err(|_| ReleaseError::InvalidBinary)?;
    file.rewind().map_err(|_| ReleaseError::InvalidBinary)?;
    let expected_machine = match target {
        "x86_64-unknown-linux-gnu" => 62_u16,
        "aarch64-unknown-linux-gnu" => 183_u16,
        _ => return Err(ReleaseError::InvalidBinary),
    };
    if header[..4] != [0x7f, b'E', b'L', b'F']
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || ![0_u8, 3_u8].contains(&header[7])
        || ![2_u16, 3_u16].contains(&u16::from_le_bytes([header[16], header[17]]))
        || u16::from_le_bytes([header[18], header[19]]) != expected_machine
    {
        return Err(ReleaseError::InvalidBinary);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_binary(_path: &Path, _target: &str) -> Result<fs::File, ReleaseError> {
    Err(ReleaseError::InvalidBinary)
}

fn create_tree_archive(source: &Path, output: &Path, epoch: u32) -> Result<(), ReleaseError> {
    let file = create_new(output)?;
    let encoder = GzBuilder::new().mtime(epoch).write(
        BoundedWriter::new(file, MAX_SOURCE_ARCHIVE_BYTES),
        Compression::best(),
    );
    let mut tar = TarBuilder::new(encoder);
    tar.mode(tar::HeaderMode::Deterministic);
    let root_name = source.file_name().ok_or(ReleaseError::Generation)?;
    append_tree(&mut tar, source, Path::new(root_name), epoch)?;
    let encoder = tar.into_inner().map_err(|_| ReleaseError::Generation)?;
    encoder
        .finish()
        .map_err(|_| ReleaseError::Generation)?
        .sync_all()
        .map_err(|_| ReleaseError::Generation)
}

fn append_tree<W: std::io::Write>(
    tar: &mut TarBuilder<W>,
    source: &Path,
    archive_path: &Path,
    epoch: u32,
) -> Result<(), ReleaseError> {
    let mut entries = fs::read_dir(source)
        .map_err(|_| ReleaseError::Generation)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ReleaseError::Generation)?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type().map_err(|_| ReleaseError::Generation)?;
        let path = entry.path();
        let member = archive_path.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(ReleaseError::Generation);
        }
        if file_type.is_dir() {
            append_tree(tar, &path, &member, epoch)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(ReleaseError::Generation);
        }
        let metadata = entry.metadata().map_err(|_| ReleaseError::Generation)?;
        let mut file = fs::File::open(path).map_err(|_| ReleaseError::Generation)?;
        let mut header = TarHeader::new_gnu();
        header.set_size(metadata.len());
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(u64::from(epoch));
        header.set_cksum();
        tar.append_data(&mut header, member, &mut file)
            .map_err(|_| ReleaseError::Generation)?;
    }
    Ok(())
}

fn supply_chain_documents(
    metadata: &CargoMetadata,
) -> Result<(CycloneDxBom, String), ReleaseError> {
    validate_metadata(metadata)?;
    let workspace = metadata
        .workspace_members
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut packages = metadata.packages.clone();
    packages.sort_by(|left, right| left.id.cmp(&right.id));
    let mut components = Vec::with_capacity(packages.len());
    let mut notices = String::from(
        "THIRD-PARTY NOTICES\n\nGenerated from the exact locked Cargo graph. License expressions are package metadata; packaged vendored source is authoritative for license texts.\n\n",
    );
    for package in packages {
        let mut properties = vec![SbomProperty {
            name: "radroots:cargo_package_id",
            value: package.id.clone(),
        }];
        if let Some(source) = package.source {
            properties.push(SbomProperty {
                name: "radroots:cargo_source",
                value: source,
            });
        }
        if let Some(checksum) = package.checksum {
            properties.push(SbomProperty {
                name: "radroots:cargo_checksum",
                value: checksum,
            });
        }
        properties.push(SbomProperty {
            name: "radroots:workspace_member",
            value: workspace.contains(&package.id).to_string(),
        });
        let licenses = package.license.as_ref().map(|license| {
            vec![SbomLicenseChoice {
                expression: license.clone(),
            }]
        });
        use fmt::Write as _;
        writeln!(
            notices,
            "{} {} — {}",
            package.name,
            package.version,
            package.license.as_deref().unwrap_or("NOASSERTION")
        )
        .map_err(|_| ReleaseError::Generation)?;
        components.push(SbomComponent {
            component_type: "library",
            bom_ref: package.id,
            name: package.name,
            version: package.version,
            licenses,
            properties,
        });
    }
    let mut dependencies = metadata
        .resolve
        .as_ref()
        .ok_or(ReleaseError::InvalidMetadata)?
        .nodes
        .iter()
        .map(|node| {
            let mut depends_on = node.dependencies.clone();
            depends_on.sort();
            depends_on.dedup();
            SbomDependency {
                reference: node.id.clone(),
                depends_on,
            }
        })
        .collect::<Vec<_>>();
    dependencies.sort_by(|left, right| left.reference.cmp(&right.reference));
    Ok((
        CycloneDxBom {
            bom_format: "CycloneDX",
            spec_version: "1.5",
            version: 1,
            metadata: SbomMetadata {
                component: SbomRootComponent {
                    component_type: "application",
                    name: SERVICE,
                    version: VERSION,
                },
            },
            components,
            dependencies,
        },
        notices,
    ))
}

#[cfg(test)]
fn validate_relative(value: &str) -> Result<(), ReleaseError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(ReleaseError::InvalidSource);
    }
    Ok(())
}

fn copy_bounded(source: &Path, output: &Path, maximum: u64) -> Result<(), ReleaseError> {
    validate_regular(source, maximum, ReleaseError::InvalidSource)?;
    let metadata = fs::metadata(source).map_err(|_| ReleaseError::InvalidSource)?;
    let mut input = fs::File::open(source).map_err(|_| ReleaseError::InvalidSource)?;
    let mut target = create_new(output)?;
    let mut scanner = SecretScanner::default();
    let mut total = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|_| ReleaseError::InvalidSource)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| ReleaseError::InvalidSource)?)
            .ok_or(ReleaseError::InvalidSource)?;
        if total > maximum {
            return Err(ReleaseError::InvalidSource);
        }
        scanner.scan(&buffer[..read])?;
        target
            .write_all(&buffer[..read])
            .map_err(|_| ReleaseError::Generation)?;
    }
    if total != metadata.len() {
        return Err(ReleaseError::InvalidSource);
    }
    target.sync_all().map_err(|_| ReleaseError::Generation)
}

fn create_new(path: &Path) -> Result<fs::File, ReleaseError> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o644);
    }
    let file = options.open(path).map_err(|_| ReleaseError::Generation)?;
    set_file_permissions(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn set_file_permissions(file: &fs::File) -> Result<(), ReleaseError> {
    use std::os::unix::fs::PermissionsExt as _;

    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|_| ReleaseError::Generation)
}

#[cfg(not(unix))]
fn set_file_permissions(_file: &fs::File) -> Result<(), ReleaseError> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), ReleaseError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|_| ReleaseError::Generation)
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), ReleaseError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ReleaseError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ReleaseError::Generation)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ReleaseError> {
    Ok(())
}

#[cfg(unix)]
fn publish_directory(source: &Path, destination: &Path) -> Result<(), ReleaseError> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};

    renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)
        .map_err(|_| ReleaseError::Generation)
}

#[cfg(not(unix))]
fn publish_directory(_source: &Path, _destination: &Path) -> Result<(), ReleaseError> {
    Err(ReleaseError::Generation)
}

struct BoundedWriter<W> {
    inner: W,
    written: u64,
    maximum: u64,
}

impl<W> BoundedWriter<W> {
    const fn new(inner: W, maximum: u64) -> Self {
        Self {
            inner,
            written: 0,
            maximum,
        }
    }
}

impl BoundedWriter<fs::File> {
    fn sync_all(&self) -> std::io::Result<()> {
        self.inner.sync_all()
    }
}

impl<W: std::io::Write> std::io::Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self.maximum.saturating_sub(self.written);
        if remaining == 0 && !bytes.is_empty() {
            return Err(std::io::Error::other("bounded output exceeded"));
        }
        let admitted = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let written = self.inner.write(&bytes[..admitted])?;
        self.written = self
            .written
            .checked_add(u64::try_from(written).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("bounded output exceeded"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ReleaseError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| ReleaseError::Generation)?;
    bytes.push(b'\n');
    write_generated(path, &bytes)
}

fn write_generated(path: &Path, bytes: &[u8]) -> Result<(), ReleaseError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(ReleaseError::Generation);
    }
    scan_bytes(bytes)?;
    let mut file = create_new(path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ReleaseError::Generation)
}

fn write_checksums(root: &Path) -> Result<(), ReleaseError> {
    let records = inventory_records(root)?;
    let mut output = String::new();
    use fmt::Write as _;
    for record in records {
        writeln!(output, "{}  {}", record.sha256, record.path)
            .map_err(|_| ReleaseError::Generation)?;
    }
    write_generated(&root.join("SHA256SUMS"), output.as_bytes())
}

fn inventory_records(root: &Path) -> Result<Vec<ArtifactRecord>, ReleaseError> {
    let mut names = fs::read_dir(root)
        .map_err(|_| ReleaseError::InvalidOutput)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ReleaseError::InvalidOutput)?;
    names.sort_by_key(fs::DirEntry::file_name);
    names
        .into_iter()
        .map(|entry| {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ReleaseError::InvalidOutput)?;
            let evidence = hash_regular(&entry.path(), output_maximum(&name)?)?;
            Ok(ArtifactRecord {
                path: name,
                byte_length: evidence.byte_length,
                sha256: evidence.sha256,
            })
        })
        .collect()
}

fn output_maximum(name: &str) -> Result<u64, ReleaseError> {
    match name {
        "binary.tar.gz" => Ok(MAX_BINARY_BYTES + MAX_TEXT_BYTES),
        "service-source.tar.gz" => Ok(MAX_SOURCE_ARCHIVE_BYTES),
        "LICENSE"
        | "config.example.toml"
        | "config.schema.json"
        | "systemd.service"
        | SOURCE_LOCK => Ok(MAX_TEXT_BYTES),
        "SHA256SUMS"
        | "THIRD-PARTY-NOTICES.txt"
        | "artifact-manifest.v1.json"
        | "provenance-input.v1.json"
        | "sbom.cdx.json" => Ok(MAX_DOCUMENT_BYTES),
        _ => Err(ReleaseError::InvalidOutput),
    }
}

fn validate_exact_inventory(root: &Path) -> Result<(), ReleaseError> {
    let actual = inventory_records(root)?;
    if actual
        .iter()
        .map(|record| record.path.as_str())
        .collect::<Vec<_>>()
        != OUTPUT_NAMES
    {
        return Err(ReleaseError::InvalidOutput);
    }
    validate_output_permissions(root)?;
    Ok(())
}

#[cfg(unix)]
fn validate_output_permissions(root: &Path) -> Result<(), ReleaseError> {
    use std::os::unix::fs::PermissionsExt as _;

    let root_metadata = fs::symlink_metadata(root).map_err(|_| ReleaseError::InvalidOutput)?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.permissions().mode() & 0o777 != 0o755
    {
        return Err(ReleaseError::InvalidOutput);
    }
    for name in OUTPUT_NAMES {
        let metadata =
            fs::symlink_metadata(root.join(name)).map_err(|_| ReleaseError::InvalidOutput)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o644
        {
            return Err(ReleaseError::InvalidOutput);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_output_permissions(_root: &Path) -> Result<(), ReleaseError> {
    Ok(())
}

fn compare_output(output: &Path, expected: &[ArtifactRecord]) -> Result<(), ReleaseError> {
    validate_exact_inventory(output)?;
    let actual = inventory_records(output)?;
    if actual != expected {
        return Err(ReleaseError::StaleOutput);
    }
    Ok(())
}

struct FileEvidence {
    byte_length: u64,
    sha256: String,
}

fn hash_regular(path: &Path, maximum: u64) -> Result<FileEvidence, ReleaseError> {
    validate_regular(path, maximum, ReleaseError::InvalidOutput)?;
    let metadata = fs::metadata(path).map_err(|_| ReleaseError::InvalidOutput)?;
    let mut file = fs::File::open(path).map_err(|_| ReleaseError::InvalidOutput)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ReleaseError::InvalidOutput)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| ReleaseError::InvalidOutput)?)
            .ok_or(ReleaseError::InvalidOutput)?;
        if total > maximum {
            return Err(ReleaseError::InvalidOutput);
        }
        hasher.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err(ReleaseError::InvalidOutput);
    }
    Ok(FileEvidence {
        byte_length: total,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn validate_regular(path: &Path, maximum: u64, error: ReleaseError) -> Result<(), ReleaseError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(error);
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64, error: ReleaseError) -> Result<Vec<u8>, ReleaseError> {
    validate_regular(path, maximum, error)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| error)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| error)?;
    if bytes.len() as u64 > maximum {
        return Err(error);
    }
    Ok(bytes)
}

fn command_capture_bounded(
    command: &mut Command,
    maximum: u64,
    error: ReleaseError,
) -> Result<Vec<u8>, ReleaseError> {
    let file = NamedTempFile::new().map_err(|_| error)?;
    let stdout = file.reopen().map_err(|_| error)?;
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null())
        .status()
        .map_err(|_| error)?;
    if !status.success() {
        return Err(error);
    }
    read_bounded(file.path(), maximum, error)
}

fn git_capture(root: &Path, arguments: &[&str], maximum: usize) -> Result<Vec<u8>, ReleaseError> {
    command_capture_bounded(
        Command::new("git").args(arguments).current_dir(root),
        maximum as u64,
        ReleaseError::InvalidSource,
    )
}

fn exact_line(bytes: &[u8]) -> Option<&str> {
    let value = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    (!value.is_empty() && !value.contains(['\n', '\r'])).then_some(value)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Default)]
struct SecretScanner {
    tail: Vec<u8>,
}

impl SecretScanner {
    fn scan(&mut self, bytes: &[u8]) -> Result<(), ReleaseError> {
        let mut combined = Vec::with_capacity(self.tail.len() + bytes.len());
        combined.extend_from_slice(&self.tail);
        combined.extend_from_slice(bytes);
        if SECRET_PATTERNS
            .iter()
            .any(|pattern| contains_bytes(&combined, pattern))
        {
            return Err(ReleaseError::ProtectedMaterial);
        }
        let retained = SECRET_PATTERNS
            .iter()
            .map(|pattern| pattern.len().saturating_sub(1))
            .max()
            .unwrap_or(0)
            .min(combined.len());
        self.tail.clear();
        self.tail
            .extend_from_slice(&combined[combined.len() - retained..]);
        Ok(())
    }
}

fn scan_bytes(bytes: &[u8]) -> Result<(), ReleaseError> {
    let mut scanner = SecretScanner::default();
    scanner.scan(bytes)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_parser_is_closed_and_bounded() {
        let args = parse_native_release_args(vec![
            "--mode".into(),
            "check".into(),
            "--target".into(),
            "x86_64-unknown-linux-gnu".into(),
            "--binary".into(),
            "/tmp/myc".into(),
            "--output".into(),
            "/tmp/release".into(),
            "--source-date-epoch".into(),
            "1".into(),
        ])
        .expect("valid arguments");
        assert_eq!(args.mode, Mode::Check);
        assert_eq!(args.source_date_epoch, 1);
        for mutation in [
            vec!["--mode".into(), "write".into()],
            vec![
                "--mode".into(),
                "write".into(),
                "--mode".into(),
                "check".into(),
                "--target".into(),
                "x86_64-unknown-linux-gnu".into(),
                "--binary".into(),
                "/tmp/myc".into(),
                "--output".into(),
                "/tmp/release".into(),
                "--source-date-epoch".into(),
                "1".into(),
            ],
            vec![
                "--mode".into(),
                "write".into(),
                "--target".into(),
                "x86_64-apple-darwin".into(),
                "--binary".into(),
                "/tmp/myc".into(),
                "--output".into(),
                "/tmp/release".into(),
                "--source-date-epoch".into(),
                "1".into(),
            ],
        ] {
            assert_eq!(
                parse_native_release_args(mutation).expect_err("invalid arguments"),
                ReleaseError::InvalidArguments
            );
        }
    }

    #[test]
    fn secret_scanner_detects_split_patterns() {
        let mut scanner = SecretScanner::default();
        scanner.scan(b"prefix github_").expect("prefix");
        assert_eq!(
            scanner.scan(b"pat_value").expect_err("secret rejected"),
            ReleaseError::ProtectedMaterial
        );
    }

    #[cfg(unix)]
    #[test]
    fn binary_archive_is_deterministic_and_contains_one_member() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TempDir::new().expect("tempdir");
        let binary = directory.path().join("myc");
        let mut elf = [0_u8; 20];
        elf[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        elf[16..18].copy_from_slice(&3_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        fs::write(&binary, elf).expect("binary");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("binary mode");
        let first = directory.path().join("first.tar.gz");
        let second = directory.path().join("second.tar.gz");
        create_binary_archive(&binary, &first, "x86_64-unknown-linux-gnu", 1)
            .expect("first archive");
        create_binary_archive(&binary, &second, "x86_64-unknown-linux-gnu", 1)
            .expect("second archive");
        assert_eq!(
            fs::read(first).expect("first"),
            fs::read(second).expect("second")
        );
        assert_eq!(
            create_binary_archive(
                &binary,
                &directory.path().join("wrong-target.tar.gz"),
                "aarch64-unknown-linux-gnu",
                1,
            )
            .expect_err("target mismatch"),
            ReleaseError::InvalidBinary
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_permissions_are_exact() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = TempDir::new().expect("tempdir");
        let directory = parent.path().join("release");
        fs::create_dir(&directory).expect("directory");
        set_directory_permissions(&directory).expect("directory mode");
        let file = directory.join("artifact");
        create_new(&file).expect("artifact");
        assert_eq!(
            fs::metadata(directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(file)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn compressed_outputs_are_bounded_before_allocation() {
        let mut writer = BoundedWriter::new(Vec::new(), 3);
        assert!(writer.write_all(b"abc").is_ok());
        assert_eq!(writer.written, 3);
        assert!(writer.write_all(b"d").is_err());
    }

    #[test]
    fn sbom_uses_spdx_expressions_in_the_governed_field() {
        assert_eq!(
            serde_json::to_value(SbomLicenseChoice {
                expression: "MIT OR Apache-2.0".to_owned(),
            })
            .expect("license choice"),
            serde_json::json!({"expression": "MIT OR Apache-2.0"})
        );
    }

    #[test]
    fn relative_paths_reject_escape_and_absolute_values() {
        for rejected in ["", "../escape", "a/../../escape", "/absolute"] {
            assert_eq!(
                validate_relative(rejected).expect_err("path rejected"),
                ReleaseError::InvalidSource
            );
        }
        validate_relative("contracts/config.json").expect("safe path");
    }

    #[test]
    fn error_surface_is_fixed_and_source_free() {
        for error in [
            ReleaseError::InvalidArguments,
            ReleaseError::InvalidSource,
            ReleaseError::DirtySource,
            ReleaseError::InvalidBinary,
            ReleaseError::InvalidOutput,
            ReleaseError::InvalidMetadata,
            ReleaseError::InvalidSourceLock,
            ReleaseError::ProtectedMaterial,
            ReleaseError::StaleOutput,
            ReleaseError::Generation,
        ] {
            assert!(!error.code().is_empty());
            let display = error.to_string();
            assert!(!display.contains('/'));
            assert!(!display.contains("github_pat"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
