mod crypto;
use clap::{Parser, Subcommand};
use crypto::{context, seal, unseal};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "ve",
    about = "Passwordless encrypted environment workspaces",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    #[command(about = "Enroll this CLI using your browser and passkey")]
    Auth,
    #[command(about = "Remove this CLI's locally stored credentials")]
    Logout,
    #[command(about = "Update ve to the latest release")]
    Update,
    #[command(about = "List organizations you belong to")]
    Workspaces,
    #[command(about = "Select an organization and existing folder for this project")]
    Init {
        #[arg(long, help = "Workspace name or ID; omit to choose a workspace")]
        org: Option<String>,
        #[arg(short, long, default_value = "")]
        path: String,
    },
    #[command(about = "Encrypt and push .env; --force also deletes missing remote keys")]
    Push {
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Decrypt into .env; --force replaces local values")]
    Pull {
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Show folders and secret names in a tree")]
    List,
    #[command(about = "Compare local and remote values without printing them")]
    Diff,
    #[command(about = "Search secret names in the selected organization")]
    Search { pattern: String },
    #[command(about = "Validate local .env syntax")]
    Validate,
    #[command(about = "Show the current authenticated account")]
    Whoami,
    #[command(about = "Test authenticated access")]
    Test,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    server: String,
    organization_id: String,
    folder_id: String,
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
fn project() -> Result<Project> {
    let mut p: Project = serde_json::from_str(
        &fs::read_to_string(".voe.json")
            .map_err(|_| "Run ve init first to select a workspace for this project")?,
    )?;
    p.server = validate_server(&p.server)?;
    Ok(p)
}
fn credential_entry(server: &str) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new("voe-cli", server)?)
}
fn credentials(server: &str) -> Result<Credentials> {
    let stored = Zeroizing::new(credential_entry(server)?.get_password().map_err(|_| {
        "No credential-store entry. Run ve auth for this server. No plaintext fallback is used."
    })?);
    let credentials: Credentials = serde_json::from_str(&stored)?;
    if credentials.expires_at <= now() {
        return Err("CLI session expired. Run ve auth again".into());
    }
    Ok(credentials)
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
    let response = request.send().await?;
    let status = response.status();
    let value: Value = response.json().await?;
    if !status.is_success() {
        return Err(format!(
            "{}: {}",
            status,
            value
                .get("message")
                .or_else(|| value.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("Request failed")
        )
        .into());
    }
    Ok(value)
}
async fn authenticate() -> Result<()> {
    let server = validate_server(&get_base_url())?;
    let entry = credential_entry(&server)?;
    let (public, private) = crypto::generate_identity()?;
    let code: DeviceCode = client()?
        .post(format!("{server}/api/auth/device/code"))
        .json(&json!({"client_id":"voe-cli"}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let enrolled: Value = client()?
        .post(format!("{server}/api/devices"))
        .json(&json!({"action":"enroll","deviceCode":code.device_code,"publicKey":public}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let device_id = enrolled["id"]
        .as_str()
        .ok_or("Missing enrollment ID")?
        .to_string();
    println!("Open {server}/device?user_code={}\nCode: {}\nDevice fingerprint: {}\nVerify this fingerprint in your browser and select workspace access.",code.user_code,code.user_code,crypto::fingerprint(&public)?);
    let deadline = Instant::now() + Duration::from_secs(code.expires_in);
    let mut interval = code.interval.max(1);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let response=client()?.post(format!("{server}/api/auth/device/token")).json(&json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code.device_code,"client_id":"voe-cli"})).send().await?;
        let success = response.status().is_success();
        let value: Value = response.json().await?;
        if success {
            let credentials = Credentials {
                access_token: value["access_token"]
                    .as_str()
                    .ok_or("Missing session token")?
                    .into(),
                private_key: private.to_string(),
                device_id,
                expires_at: now()
                    + value["expires_in"]
                        .as_u64()
                        .ok_or("Missing session expiry")?,
            };
            let serialized = Zeroizing::new(serde_json::to_string(&credentials)?);
            entry.set_password(&serialized).map_err(|e| {
                format!("Could not store credentials in the OS credential store: {e}")
            })?;
            println!("Device enrolled. Credentials are stored in your OS credential store.");
            return Ok(());
        }
        match value["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            _ => {
                return Err(value["error_description"]
                    .as_str()
                    .unwrap_or("Device authorization failed")
                    .into())
            }
        }
    }
    Err("Device authorization expired. Run ve auth again".into())
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
        let folder = folders
            .iter()
            .find(|f| f.id == id)
            .ok_or("Folder not found")?;
        if folder.parent_id.is_some() {
            parts.push(folder.name.clone());
        }
        current = folder.parent_id.as_deref();
    }
    parts.reverse();
    Ok(parts.join(":"))
}
fn folder_key(
    snapshot: &Snapshot,
    credentials: &Credentials,
    id: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let recipient = format!("device:{}", credentials.device_id);
    let envelope = snapshot
        .envelopes
        .iter()
        .find(|e| e.recipient == recipient)
        .ok_or("No key envelope for this CLI. Run ve auth to enroll it.")?;
    let org = crypto::unwrap(
        &credentials.private_key,
        &envelope.wrapped_key,
        &context(json!([
            "organization",
            snapshot.organization_id,
            recipient,
            snapshot.epoch
        ])),
    )?;
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
fn local_values() -> Result<BTreeMap<String, String>> {
    if !Path::new(".env").exists() {
        return Ok(BTreeMap::new());
    }
    let mut values = BTreeMap::new();
    for entry in dotenvy::from_path_iter(".env")? {
        let (key, value) = entry?;
        if !regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$")?.is_match(&key) {
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
fn write_env(values: &BTreeMap<String, String>) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(".")?;
    file.write_all(env_content(values).as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(".env")?;
    Ok(())
}
fn workspace_choices<'a>(
    workspaces: &'a [Workspace],
    selector: Option<&str>,
) -> Result<Vec<&'a Workspace>> {
    if workspaces.is_empty() {
        return Err("No workspaces found. Create or join a workspace in the web app first.".into());
    }
    let mut choices: Vec<_> = if let Some(selector) = selector {
        let selector = selector.trim();
        if let Some(workspace) = workspaces.iter().find(|workspace| workspace.id == selector) {
            return Ok(vec![workspace]);
        }
        let matches: Vec<_> = workspaces
            .iter()
            .filter(|workspace| workspace.name.to_lowercase() == selector.to_lowercase())
            .collect();
        if matches.is_empty() {
            return Err(format!(
                "Workspace {selector:?} not found. Run ve workspaces to see your available workspaces."
            )
            .into());
        }
        matches
    } else {
        workspaces.iter().collect()
    };
    choices.sort_by_key(|workspace| (workspace.name.to_lowercase(), &workspace.id));
    Ok(choices)
}
fn choose_workspace<'a>(choices: &[&'a Workspace]) -> Result<&'a Workspace> {
    if let [workspace] = choices {
        return Ok(workspace);
    }
    if !io::stdin().is_terminal() {
        return Err("Multiple workspaces match. Pass --org with a unique workspace name or ID, or run ve init in a terminal to choose.".into());
    }
    println!("Choose a workspace:");
    for (index, workspace) in choices.iter().enumerate() {
        println!(
            "  {}. {} ({}) [{}]",
            index + 1,
            workspace.name,
            workspace.role,
            workspace.id
        );
    }
    print!("Workspace number: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let selected = input
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|number| number.checked_sub(1))
        .and_then(|index| choices.get(index));
    selected.copied().ok_or_else(|| {
        "Invalid workspace selection. Run ve init again and choose a listed number.".into()
    })
}
async fn init(org: Option<String>, folder_path: String) -> Result<()> {
    let server = validate_server(&get_base_url())?;
    let credentials = credentials(&server)?;
    let workspaces: Vec<Workspace> =
        serde_json::from_value(request(&server, &credentials, "/api/workspaces", None).await?)?;
    let choices = workspace_choices(&workspaces, org.as_deref())?;
    let workspace = choose_workspace(&choices)?;
    let mut project = Project {
        server,
        organization_id: workspace.id.clone(),
        folder_id: String::new(),
    };
    let snapshot = snapshot(&project, &credentials).await?;
    let folder = snapshot
        .folders
        .iter()
        .find(|f| path(&snapshot.folders, &f.id).ok().as_deref() == Some(folder_path.as_str()))
        .ok_or("Folder not found. Create it in the workspace first.")?;
    folder_key(&snapshot, &credentials, &folder.id)?;
    project.folder_id = folder.id.clone();
    let mut file = tempfile::NamedTempFile::new_in(".")?;
    file.write_all(serde_json::to_string_pretty(&project)?.as_bytes())?;
    file.persist(".voe.json")?;
    let selected_path = if folder_path.is_empty() {
        "/"
    } else {
        &folder_path
    };
    println!("Project configured: {} ({selected_path})", workspace.name);
    Ok(())
}
async fn push(force: bool) -> Result<()> {
    let project = project()?;
    let credentials = credentials(&project.server)?;
    let mut snapshot = snapshot(&project, &credentials).await?;
    if snapshot.rotation_required {
        return Err("Workspace key rotation is required. Open workspace settings.".into());
    }
    if snapshot.role == "viewer" {
        return Err("Viewers cannot write secrets".into());
    }
    if !Path::new(".env").exists() {
        return Err("No .env file to push".into());
    }
    let values = local_values()?;
    let key = folder_key(&snapshot, &credentials, &project.folder_id)?;
    if force {
        snapshot
            .secrets
            .retain(|s| s.folder_id != project.folder_id || values.contains_key(&s.name));
    }
    for (name, value) in &values {
        let id = snapshot
            .secrets
            .iter()
            .find(|s| s.folder_id == project.folder_id && s.name == *name)
            .map(|s| s.id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let encrypted_value = seal(
            &key,
            value.as_bytes(),
            &context(json!([
                "secret",
                snapshot.organization_id,
                project.folder_id,
                id,
                name,
                snapshot.epoch
            ])),
        )?;
        snapshot.secrets.retain(|s| s.id != id);
        snapshot.secrets.push(Secret {
            id,
            folder_id: project.folder_id.clone(),
            name: name.clone(),
            encrypted_value,
        });
    }
    let body = json!({"action":"save","revision":snapshot.revision,"epoch":snapshot.epoch,"folders":snapshot.folders,"secrets":snapshot.secrets});
    request(
        &project.server,
        &credentials,
        &format!("/api/workspaces/{}", project.organization_id),
        Some(body),
    )
    .await?;
    println!("Pushed {} encrypted secrets.", values.len());
    Ok(())
}
async fn pull(force: bool) -> Result<()> {
    let project = project()?;
    let credentials = credentials(&project.server)?;
    let snapshot = snapshot(&project, &credentials).await?;
    let remote = remote_values(&snapshot, &credentials, &project.folder_id)?;
    let mut values = local_values()?;
    if !force
        && remote
            .iter()
            .any(|(k, v)| values.get(k).is_some_and(|old| old != v))
    {
        return Err(
            "Local values differ. Use ve diff, then ve pull --force to replace .env.".into(),
        );
    }
    if force {
        values = remote;
    } else {
        values.extend(remote);
    }
    write_env(&values)?;
    println!(
        "Wrote {} secrets to .env (without a vault password).",
        values.len()
    );
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
async fn inspect(command: &Commands) -> Result<()> {
    let project = project()?;
    let credentials = credentials(&project.server)?;
    let snapshot = snapshot(&project, &credentials).await?;
    match command {
        Commands::Diff => {
            let local = local_values()?;
            let remote = remote_values(&snapshot, &credentials, &project.folder_id)?;
            for key in local
                .keys()
                .chain(remote.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                let status = match (local.get(key), remote.get(key)) {
                    (Some(a), Some(b)) if a == b => "same",
                    (Some(_), Some(_)) => "changed",
                    (Some(_), None) => "local only",
                    _ => "remote only",
                };
                println!("{status}: {key}");
            }
        }
        Commands::List => {
            print!("{}", workspace_tree(&snapshot.folders, &snapshot.secrets)?);
        }
        Commands::Search { pattern } => {
            for secret in snapshot
                .secrets
                .iter()
                .filter(|s| s.name.to_lowercase().contains(&pattern.to_lowercase()))
            {
                println!(
                    "{}:{}",
                    path(&snapshot.folders, &secret.folder_id)?,
                    secret.name
                );
            }
        }
        _ => {}
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Auth => authenticate().await,
        Commands::Logout => {
            credential_entry(&validate_server(&get_base_url())?)?.delete_credential()?;
            println!("Local credentials removed. Revoke the device in workspace settings to remove server access.");
            Ok(())
        }
        Commands::Update => cmd_update().await,
        Commands::Init { org, path } => init(org, path).await,
        Commands::Push { force } => push(force).await,
        Commands::Pull { force } => pull(force).await,
        Commands::Workspaces => {
            let server = validate_server(&get_base_url())?;
            let credentials = credentials(&server)?;
            let workspaces = request(&server, &credentials, "/api/workspaces", None).await?;
            for org in workspaces.as_array().ok_or("Invalid workspace response")? {
                println!(
                    "{}  {}  ({})",
                    org["id"].as_str().unwrap_or(""),
                    org["name"].as_str().unwrap_or(""),
                    org["role"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Commands::Whoami | Commands::Test => {
            let server = validate_server(&get_base_url())?;
            let credentials = credentials(&server)?;
            let value = request(&server, &credentials, "/api/test", None).await?;
            println!(
                "{}",
                value["user"]["email"].as_str().unwrap_or("Authenticated")
            );
            Ok(())
        }
        Commands::Validate => {
            println!("{} valid environment variables.", local_values()?.len());
            Ok(())
        }
        command => inspect(&command).await,
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
async fn cmd_update() -> Result<()> {
    let (asset, header): (&str, &[u8]) = match (env::consts::OS, env::consts::ARCH) {
        ("macos", "x86_64") => ("ve-darwin-amd64", b"\xcf\xfa\xed\xfe"),
        ("macos", "aarch64") => ("ve-darwin-arm64", b"\xcf\xfa\xed\xfe"),
        ("linux", "x86_64") => ("ve-linux-amd64", b"\x7fELF"),
        ("linux", "aarch64") => ("ve-linux-arm64", b"\x7fELF"),
        ("windows", "x86_64") => ("ve-windows-amd64.exe", b"MZ"),
        ("windows", "aarch64") => ("ve-windows-arm64.exe", b"MZ"),
        _ => return Err("Updates are not supported on this platform".into()),
    };

    println!("Downloading the latest ve...");
    let binary = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?
        .get(format!("{}/downloads/{}", get_base_url(), asset))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    if !binary.starts_with(header) {
        return Err("The download is not a valid executable for this platform".into());
    }

    let mut download = tempfile::NamedTempFile::new()?;
    download.write_all(&binary)?;
    download.flush()?;
    self_replace::self_replace(download.path())?;
    println!("Updated ve.");
    Ok(())
}
