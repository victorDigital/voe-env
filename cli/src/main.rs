mod update;
use update::cmd_update;
mod args;
mod project;
use args::*;
use project::*;
mod setup;
mod sync;
use setup::*;
use sync::*;
mod credential_store;
mod crypto;
use clap::{Parser, Subcommand};
use credential_store::CredentialStore;
use crypto::{context, seal, unseal};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressFinish, ProgressStyle};
use rand::RngCore;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    server: String,
    organization_id: String,
    folder_id: String,
    #[serde(skip)]
    root: PathBuf,
}
#[derive(Deserialize)]
struct Workspace {
    id: String,
    name: String,
    role: String,
}
#[derive(Serialize, Deserialize)]
struct Credentials {
    access_token: String,
    private_key: String,
    device_id: String,
    expires_at: u64,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.private_key.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Folder {
    id: String,
    parent_id: Option<String>,
    name: String,
    wrapped_key: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Secret {
    id: String,
    folder_id: String,
    name: String,
    encrypted_value: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    recipient: String,
    wrapped_key: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    organization_id: String,
    epoch: u64,
    revision: u64,
    rotation_required: bool,
    role: String,
    folders: Vec<Folder>,
    secrets: Vec<Secret>,
    envelopes: Vec<Envelope>,
}
#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    expires_in: u64,
    interval: u64,
}
fn get_voe_dir() -> PathBuf {
    PathBuf::from(
        env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .unwrap_or_default(),
    )
    .join(".voe")
}
fn get_base_url() -> String {
    env::var("VOE_BASE_URL")
        .ok()
        .or_else(|| fs::read_to_string(get_voe_dir().join("server-url")).ok())
        .unwrap_or_else(|| "https://env.voe.dk".into())
        .trim()
        .trim_end_matches('/')
        .to_string()
}
fn validate_server(value: &str) -> Result<String> {
    let url = reqwest::Url::parse(value)?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("Use an HTTPS server origin (HTTP is allowed only for localhost)".into());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
async fn request(
    server: &str,
    credentials: &Credentials,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let request = client()?
        .request(
            if body.is_some() {
                Method::POST
            } else {
                Method::GET
            },
            format!("{server}{path}"),
        )
        .bearer_auth(&credentials.access_token);
    let request = if let Some(body) = body {
        request.json(&body)
    } else {
        request
    };
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            format!("Request to {server} timed out. Check your connection and retry.")
        } else {
            format!("Could not reach {server}. Check your connection and the server in .voe.json.")
        }
    })?;
    let status = response.status();
    let value = response.json::<Value>().await;
    if !status.is_success() {
        let hint = match status.as_u16() {
            401 => " Run ve auth to sign in again.",
            403 => " Check your workspace access in the web app.",
            409 => " Run ve diff and review remote changes before retrying; complete any required key rotation in the web app.",
            429 => " Wait a moment before retrying.",
            500..=599 => " Check server availability and retry.",
            _ => "",
        };
        return Err(format!(
            "{}: {}{}",
            status,
            value
                .as_ref()
                .ok()
                .and_then(|value| value.get("message").or_else(|| value.get("error")))
                .and_then(Value::as_str)
                .unwrap_or("Request failed"),
            hint
        )
        .into());
    }
    value.map_err(|_| {
        format!("Invalid response from {server}. Check server availability and retry.").into()
    })
}
async fn snapshot(project: &Project, credentials: &Credentials) -> Result<Snapshot> {
    Ok(serde_json::from_value(
        request(
            &project.server,
            credentials,
            &format!("/api/workspaces/{}", project.organization_id),
            None,
        )
        .await?,
    )?)
}
fn path(folders: &[Folder], id: &str) -> Result<String> {
    let mut parts = Vec::new();
    let mut current = Some(id);
    let mut count = 0;
    while let Some(id) = current {
        count += 1;
        if count > 64 {
            return Err("Invalid folder tree".into());
        }
        let folder = folders.iter().find(|f| f.id == id).ok_or(
            "Folder not found. Run ve init from the project root to choose an existing folder.",
        )?;
        if folder.parent_id.is_some() {
            parts.push(folder.name.clone());
        }
        current = folder.parent_id.as_deref();
    }
    parts.reverse();
    Ok(parts.join(":"))
}
fn organization_key(snapshot: &Snapshot, credentials: &Credentials) -> Result<Zeroizing<Vec<u8>>> {
    let recipient = format!("device:{}", credentials.device_id);
    let envelope = snapshot
        .envelopes
        .iter()
        .find(|e| e.recipient == recipient)
        .ok_or("No key envelope for this CLI. Run ve auth to enroll it.")?;
    crypto::unwrap(
        &credentials.private_key,
        &envelope.wrapped_key,
        &context(json!([
            "organization",
            snapshot.organization_id,
            recipient,
            snapshot.epoch
        ])),
    )
}
fn folder_key(
    snapshot: &Snapshot,
    credentials: &Credentials,
    id: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let org = organization_key(snapshot, credentials)?;
    let folder = snapshot
        .folders
        .iter()
        .find(|f| f.id == id)
        .ok_or("Project folder no longer exists")?;
    unseal(
        &org,
        &folder.wrapped_key,
        &context(json!([
            "folder",
            snapshot.organization_id,
            id,
            snapshot.epoch
        ])),
    )
}
fn remote_values(
    snapshot: &Snapshot,
    credentials: &Credentials,
    folder: &str,
) -> Result<BTreeMap<String, String>> {
    let key = folder_key(snapshot, credentials, folder)?;
    snapshot
        .secrets
        .iter()
        .filter(|s| s.folder_id == folder)
        .map(|s| {
            let raw = unseal(
                &key,
                &s.encrypted_value,
                &context(json!([
                    "secret",
                    snapshot.organization_id,
                    folder,
                    s.id,
                    s.name,
                    snapshot.epoch
                ])),
            )?;
            Ok((s.name.clone(), String::from_utf8(raw.to_vec())?))
        })
        .collect()
}
fn local_values_at(file: &Path) -> Result<BTreeMap<String, String>> {
    if !file.try_exists()? {
        return Ok(BTreeMap::new());
    }
    let mut values = BTreeMap::new();
    let key_pattern = regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$")?;
    for entry in dotenvy::from_path_iter(file)? {
        let (key, value) = entry.map_err(|_| format!("Invalid environment syntax in {}. Check quoting and KEY=value entries, then run ve validate.", file.display()))?;
        if !key_pattern.is_match(&key) {
            return Err(format!("Invalid key: {key}").into());
        }
        if values.insert(key.clone(), value).is_some() {
            return Err(format!("Duplicate key: {key}").into());
        }
    }
    Ok(values)
}
fn env_content(values: &BTreeMap<String, String>) -> String {
    let mut content = String::new();
    for (key, value) in values {
        let value = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
            .replace('\n', "\\n");
        content.push_str(&format!("{key}=\"{value}\"\n"));
    }
    content
}
fn write_env_at(destination: &Path, values: &BTreeMap<String, String>) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(destination.parent().unwrap_or(Path::new(".")))?;
    file.write_all(env_content(values).as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(destination)?;
    Ok(())
}
fn workspace_tree(folders: &[Folder], secrets: &[Secret]) -> Result<String> {
    enum Pending<'a> {
        Folder(&'a str, String),
        Line(String),
    }
    let root = folders
        .iter()
        .find(|folder| folder.parent_id.is_none())
        .ok_or("Workspace root folder not found")?;
    let mut children: BTreeMap<&str, Vec<(&str, Option<&str>)>> = BTreeMap::new();
    for folder in folders {
        path(folders, &folder.id)?;
        if let Some(parent) = folder.parent_id.as_deref() {
            children
                .entry(parent)
                .or_default()
                .push((&folder.name, Some(&folder.id)));
        }
    }
    for secret in secrets {
        children
            .entry(&secret.folder_id)
            .or_default()
            .push((&secret.name, None));
    }
    for entries in children.values_mut() {
        entries.sort_by_key(|(name, folder)| (folder.is_none(), *name));
    }
    let mut output = format!("📂 Workspace ({} secrets):\n\n", secrets.len());
    let mut pending = vec![Pending::Folder(&root.id, String::new())];
    while let Some(item) = pending.pop() {
        let (folder_id, prefix) = match item {
            Pending::Folder(id, prefix) => (id, prefix),
            Pending::Line(line) => {
                output.push_str(&line);
                continue;
            }
        };
        let Some(entries) = children.get(folder_id) else {
            continue;
        };
        for (index, (name, child_id)) in entries.iter().enumerate().rev() {
            let last = index + 1 == entries.len();
            let connector = if last { "└── " } else { "├── " };
            let icon = if child_id.is_some() { "📁" } else { "🔑" };
            let line = format!("{prefix}{connector}{icon} {name}\n");
            if let Some(child_id) = child_id {
                let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
                pending.push(Pending::Folder(child_id, child_prefix));
            }
            pending.push(Pending::Line(line));
        }
    }
    if !children.contains_key(root.id.as_str()) {
        output.push_str("No folders or secrets yet.\n");
    }
    Ok(output)
}
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(&cli.options, cli.command).await {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            if error.kind() == io::ErrorKind::BrokenPipe {
                return;
            }
        }
        if cli.options.json {
            eprintln!("{}", json!({"error": error.to_string()}));
        } else {
            eprintln!("Error: {error}");
        }
        std::process::exit(1);
    }
}

async fn run(options: &Options, command: Commands) -> Result<()> {
    match command {
        Commands::Auth => authenticate(options).await,
        Commands::Logout => {
            let server = active_server()?;
            CredentialStore::new(&server)?.delete()?;
            options.emit(&json!({"loggedOut":true,"server":server}), "Local credentials removed. Revoke the device in account settings to remove server access.")
        }
        Commands::Update => cmd_update(options).await,
        Commands::Init { org, path } => init(options, org, path).await,
        Commands::Status => status(options).await,
        Commands::Push { force, dry_run } => push(options, force, dry_run).await,
        Commands::Pull {
            force,
            dry_run,
            conflicts,
        } => pull(options, force, dry_run, conflicts).await,
        Commands::Workspaces => {
            let server = active_server()?;
            let credentials = credentials(&server)?;
            let workspaces = request(&server, &credentials, "/api/workspaces", None).await?;
            let lines = workspaces
                .as_array()
                .ok_or("Invalid workspace response")?
                .iter()
                .map(|org| {
                    format!(
                        "{}  {}  ({})",
                        org["name"].as_str().unwrap_or(""),
                        org["id"].as_str().unwrap_or(""),
                        org["role"].as_str().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>();
            let human = if lines.is_empty() {
                "No workspaces found. Create or join a workspace in the web app.".into()
            } else {
                lines.join("\n")
            };
            options.emit(&json!({"server":server,"workspaces":workspaces}), &human)
        }
        Commands::Whoami | Commands::Test => {
            let server = active_server()?;
            let credentials = credentials(&server)?;
            let value = request(&server, &credentials, "/api/test", None).await?;
            let email = value["user"]["email"].as_str().unwrap_or("Authenticated");
            options.emit(
                &json!({"server":server,"authenticated":true,"email":email}),
                email,
            )
        }
        Commands::Validate => {
            let root = find_project()?
                .map(|project| project.root)
                .unwrap_or(env::current_dir()?);
            let file = root.join(&options.file);
            if !file.try_exists()? {
                return Err(format!(
                    "No environment file at {}. Run ve pull or select a file with --file.",
                    file.display()
                )
                .into());
            }
            let count = local_values_at(&file)?.len();
            options.emit(
                &json!({"file":file,"valid":true,"variables":count}),
                &format!("{}: {count} valid environment variables.", file.display()),
            )
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut buffer = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "ve", &mut buffer);
            let script = String::from_utf8(buffer)?;
            options.emit(&json!({"shell":shell.to_string(),"script":script}), &script)
        }
        command => inspect(options, &command).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn list_renders_nested_and_empty_folders_without_secret_values() {
        let folder = |id: &str, parent: Option<&str>, name: &str| Folder {
            id: id.into(),
            parent_id: parent.map(str::to_string),
            name: name.into(),
            wrapped_key: "private-folder-key".into(),
        };
        let secret = |folder: &str, name: &str| Secret {
            id: format!("{folder}-{name}"),
            folder_id: folder.into(),
            name: name.into(),
            encrypted_value: "private-secret-value".into(),
        };
        let folders = [
            folder("prod", Some("app"), "production"),
            folder("empty", Some("root"), "empty"),
            folder("app", Some("root"), "infood"),
            folder("root", None, ""),
        ];
        let secrets = [
            secret("root", "ROOT_KEY"),
            secret("prod", "DATABASE_URL"),
            secret("app", "production"),
            secret("prod", "API_KEY"),
        ];
        assert_eq!(
            workspace_tree(&folders, &secrets).unwrap(),
            concat!(
                "📂 Workspace (4 secrets):\n\n",
                "├── 📁 empty\n",
                "├── 📁 infood\n",
                "│   ├── 📁 production\n",
                "│   │   ├── 🔑 API_KEY\n",
                "│   │   └── 🔑 DATABASE_URL\n",
                "│   └── 🔑 production\n",
                "└── 🔑 ROOT_KEY\n",
            )
        );
        assert_eq!(
            workspace_tree(&[folder("root", None, "")], &[]).unwrap(),
            "📂 Workspace (0 secrets):\n\nNo folders or secrets yet.\n"
        );
    }
    fn folder_snapshot() -> Snapshot {
        Snapshot {
            organization_id: "test-org".into(),
            epoch: 3,
            revision: 7,
            rotation_required: false,
            role: "owner".into(),
            folders: vec![Folder {
                id: "root".into(),
                parent_id: None,
                name: String::new(),
                wrapped_key: "existing-root-key".into(),
            }],
            secrets: vec![Secret {
                id: "secret".into(),
                folder_id: "root".into(),
                name: "API_KEY".into(),
                encrypted_value: "existing-ciphertext".into(),
            }],
            envelopes: vec![],
        }
    }
    #[test]
    fn folder_chooser_selects_root_and_nested_folders_and_retries_invalid_input() {
        let mut snapshot = folder_snapshot();
        let id = create_folder_path(&mut snapshot, &[7; 32], "app:production").unwrap();
        snapshot.folders.reverse();
        let mut output = Vec::new();
        let selected =
            choose_folder(&snapshot, &mut &b"0\n99\ninvalid\n3\n"[..], &mut output).unwrap();
        assert!(matches!(selected, FolderSelection::Existing(selected) if selected == id));
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("1. / (root)\n  2. app\n  3. app:production"));
        assert!(!output.contains("existing-ciphertext"));
        let selected = choose_folder(&snapshot, &mut &b"1\n"[..], &mut Vec::new()).unwrap();
        assert!(matches!(selected, FolderSelection::Existing(id) if id == "root"));
        assert!(choose_folder(&snapshot, &mut &b""[..], &mut Vec::new()).is_err());
    }
    #[test]
    fn folder_chooser_prompts_for_a_valid_new_path() {
        let snapshot = folder_snapshot();
        let selected = choose_folder(
            &snapshot,
            &mut &b"n\n\napp::production\napp:production\n"[..],
            &mut Vec::new(),
        )
        .unwrap();
        assert!(matches!(selected, FolderSelection::Create(path) if path == "app:production"));
        assert!(choose_folder(&snapshot, &mut &b"n\n"[..], &mut Vec::new()).is_err());
    }
    #[test]
    fn nested_creation_reuses_existing_folders_and_wraps_independent_keys() {
        let mut snapshot = folder_snapshot();
        let original = serde_json::to_value(&snapshot).unwrap();
        let key = [7; 32];
        let parent = create_folder_path(&mut snapshot, &key, "app").unwrap();
        let parent_envelope = snapshot.folders[1].wrapped_key.clone();
        let id = create_folder_path(&mut snapshot, &key, "app:production").unwrap();
        assert_eq!(path(&snapshot.folders, &id).unwrap(), "app:production");
        assert_eq!(
            snapshot.folders[2].parent_id.as_deref(),
            Some(parent.as_str())
        );
        let keys: Vec<_> = snapshot.folders[1..]
            .iter()
            .map(|folder| {
                unseal(
                    &key,
                    &folder.wrapped_key,
                    &context(json!([
                        "folder",
                        snapshot.organization_id,
                        folder.id,
                        snapshot.epoch
                    ])),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(keys[0].len(), 32);
        assert_eq!(keys[1].len(), 32);
        assert_ne!(*keys[0], *keys[1]);
        assert_eq!(snapshot.folders[1].wrapped_key, parent_envelope);
        assert_eq!(
            create_folder_path(&mut snapshot, &key, "app:production").unwrap(),
            id
        );
        assert_eq!(snapshot.folders.len(), 3);
        let saved = serde_json::to_value(&snapshot).unwrap();
        for field in ["secrets", "revision", "epoch", "envelopes"] {
            assert_eq!(saved[field], original[field]);
        }
        assert_eq!(saved["folders"][0], original["folders"][0]);
        assert!(unseal(
            &key,
            &snapshot.folders[2].wrapped_key,
            &context(json!(["folder", "different-org", id, snapshot.epoch]))
        )
        .is_err());
    }
    #[test]
    fn creation_rejects_invalid_paths_without_changing_the_snapshot() {
        let mut snapshot = folder_snapshot();
        let original = serde_json::to_value(&snapshot).unwrap();
        for path in ["", ":app", "app:", "app::prod", "app: ", "app:\t", "/"] {
            assert!(create_folder_path(&mut snapshot, &[7; 32], path).is_err());
        }
        assert!(validate_folder_path(&"x".repeat(129)).is_err());
        assert!(validate_folder_path(&"😀".repeat(65)).is_err());
        assert!(validate_folder_path(&vec!["x"; 64].join(":")).is_err());
        assert!(validate_folder_path(&vec!["x"; 63].join(":")).is_ok());
        assert!(create_folder_path(&mut snapshot, &[7; 31], "app").is_err());
        assert_eq!(serde_json::to_value(&snapshot).unwrap(), original);
    }
    #[test]
    fn viewers_and_pending_rotation_allow_selection_but_prevent_creation() {
        for (role, rotation_required) in [("viewer", false), ("owner", true)] {
            let mut snapshot = folder_snapshot();
            snapshot.role = role.into();
            snapshot.rotation_required = rotation_required;
            let mut output = Vec::new();
            let selected = choose_folder(&snapshot, &mut &b"n\n1\n"[..], &mut output).unwrap();
            assert!(matches!(selected, FolderSelection::Existing(id) if id == "root"));
            assert!(!String::from_utf8(output).unwrap().contains("n. Create"));
            assert!(create_folder_path(&mut snapshot, &[7; 32], "app").is_err());
            assert_eq!(snapshot.folders.len(), 1);
        }
    }
    #[test]
    fn init_distinguishes_omitted_and_explicit_folder_paths() {
        let cli = Cli::try_parse_from(["ve", "init"]).unwrap();
        assert!(matches!(cli.command, Commands::Init { path: None, .. }));
        for expected in ["", "/", "app:production"] {
            let cli = Cli::try_parse_from(["ve", "init", "--path", expected]).unwrap();
            assert!(
                matches!(cli.command, Commands::Init { path: Some(path), .. } if path == expected)
            );
        }
    }
    fn workspace(id: &str, name: &str) -> Workspace {
        Workspace {
            id: id.into(),
            name: name.into(),
            role: "owner".into(),
        }
    }
    #[test]
    fn init_accepts_names_and_an_omitted_workspace() {
        let cli = Cli::try_parse_from(["ve", "init"]).unwrap();
        assert!(matches!(cli.command, Commands::Init { org: None, .. }));
        let cli = Cli::try_parse_from(["ve", "init", "--org", "wemuda"]).unwrap();
        assert!(matches!(cli.command, Commands::Init { org: Some(name), .. } if name == "wemuda"));
        let workspaces = [workspace("opaque-id", "Wemuda")];
        for selector in [None, Some("wemuda"), Some(" WEMUDA "), Some("opaque-id")] {
            let choices = workspace_choices(&workspaces, selector).unwrap();
            assert_eq!(choose_workspace(&choices).unwrap().id, "opaque-id");
        }
    }
    #[test]
    fn workspace_matching_never_guesses_an_ambiguous_or_missing_name() {
        let workspaces = [workspace("b", "Wemuda"), workspace("a", "wemuda")];
        let choices = workspace_choices(&workspaces, Some("wemuda")).unwrap();
        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0].id, "a");
        assert_eq!(workspace_choices(&workspaces, None).unwrap().len(), 2);
        assert!(workspace_choices(&workspaces, Some("wem")).is_err());
        assert!(workspace_choices(&workspaces, Some("")).is_err());
        assert!(workspace_choices(&[], None).is_err());
    }
    #[test]
    fn exact_workspace_ids_take_priority_over_names() {
        let workspaces = [workspace("a", "Other"), workspace("b", "a")];
        let choices = workspace_choices(&workspaces, Some("a")).unwrap();
        assert_eq!(choose_workspace(&choices).unwrap().id, "a");
    }
    #[test]
    fn rejects_insecure_servers() {
        assert!(validate_server("http://example.com").is_err());
        assert!(validate_server("https://user:pass@example.com").is_err());
        assert!(validate_server("https://example.com/path").is_err());
        assert!(validate_server("http://localhost:5173").is_ok());
    }
    #[test]
    fn dotenv_round_trip() {
        let values = BTreeMap::from([(
            "TEST".into(),
            "quotes \" slash \\ dollar ${HOME}\nsecond line\r".into(),
        )]);
        let encoded = env_content(&values);
        let parsed: std::result::Result<BTreeMap<_, _>, _> =
            dotenvy::from_read_iter(encoded.as_bytes()).collect();
        assert_eq!(parsed.unwrap(), values);
    }
}
