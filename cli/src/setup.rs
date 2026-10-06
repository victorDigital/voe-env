use super::*;

pub(super) async fn authenticate(options: &Options) -> Result<()> {
    let server = active_server()?;
    authenticate_for(options, &server).await?;
    options.emit(
        &json!({"authenticated": true, "server": server, "next_command": "ve init"}),
        "Device enrolled. Credentials are stored in your OS credential store.
Next: ve init",
    )
}

fn approval_url(server: &str, user_code: &str, fingerprint: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(&format!("{server}/device"))?;
    url.query_pairs_mut()
        .append_pair("user_code", user_code)
        .append_pair("fingerprint", fingerprint);
    Ok(url)
}

fn open_browser(url: &reqwest::Url) -> Result<()> {
    use std::process::{Command, Stdio};
    let mut command = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(target_os = "windows") {
        let mut command = Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    } else {
        Command::new("xdg-open")
    };
    let status = command
        .arg(url.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("The browser launcher failed".into());
    }
    Ok(())
}

async fn authenticate_for(options: &Options, server: &str) -> Result<()> {
    let progress = OperationProgress::new(options, "Preparing device enrollment")?;
    let store = CredentialStore::new(server)?;
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
    let fingerprint = crypto::fingerprint(&public)?;
    let url = approval_url(server, &code.user_code, &fingerprint)?;
    drop(progress);
    eprintln!("Open {url}\nCode: {}\nDevice fingerprint: {fingerprint}\nConfirm the fingerprint in your browser and select workspace access.", code.user_code);
    if options.interactive() && !options.no_browser && open_browser(&url).is_err() {
        eprintln!("Could not open your browser. Open the URL above to continue.");
    }
    let deadline = Instant::now() + Duration::from_secs(code.expires_in);
    let _progress = OperationProgress::new(options, "Waiting for browser approval")?;
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
            store.save(&serialized)?;
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
pub(super) fn workspace_choices<'a>(
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
pub(super) fn choose_workspace<'a>(choices: &[&'a Workspace]) -> Result<&'a Workspace> {
    if let [workspace] = choices {
        return Ok(workspace);
    }
    if !io::stdin().is_terminal() {
        return Err("Multiple workspaces match. Pass --org with a unique workspace name or ID, or run ve init in a terminal to choose.".into());
    }
    choose_workspace_with_reader(choices, &mut io::stdin().lock(), &mut io::stderr().lock())
}

fn choose_workspace_with_reader<'a>(
    choices: &[&'a Workspace],
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<&'a Workspace> {
    let mut visible = choices.to_vec();
    loop {
        writeln!(
            output,
            "Choose a workspace (type text to filter, / to reset, q to cancel):"
        )?;
        for (index, workspace) in visible.iter().enumerate() {
            writeln!(
                output,
                "  {}. {} ({}) [{}]",
                index + 1,
                workspace.name,
                workspace.role,
                workspace.id
            )?;
        }
        let selected = prompt(input, output, "Workspace number or search: ")?;
        if selected.eq_ignore_ascii_case("q") {
            return Err("Setup cancelled. Project configuration was not changed.".into());
        }
        if selected == "/" {
            visible = choices.to_vec();
        } else if let Ok(number) = selected.parse::<usize>() {
            if let Some(workspace) = number.checked_sub(1).and_then(|index| visible.get(index)) {
                return Ok(workspace);
            }
            writeln!(output, "Invalid selection. Choose a listed number.")?;
        } else {
            let query = selected.to_lowercase();
            let matches: Vec<_> = choices
                .iter()
                .copied()
                .filter(|workspace| {
                    workspace.name.to_lowercase().contains(&query)
                        || workspace.id.to_lowercase().contains(&query)
                })
                .collect();
            if matches.is_empty() {
                writeln!(
                    output,
                    "No matching workspaces. Try another search or / to reset."
                )?;
            } else {
                visible = matches;
            }
        }
    }
}

pub(super) enum FolderSelection {
    Existing(String),
    Create(String),
}
pub(super) fn prompt(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
) -> Result<String> {
    write!(output, "{label}")?;
    output.flush()?;
    let mut value = String::new();
    if input.read_line(&mut value)? == 0 {
        return Err("Input closed. Project configuration was not changed.".into());
    }
    Ok(value.trim().to_string())
}
pub(super) fn choose_folder(
    snapshot: &Snapshot,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<FolderSelection> {
    let mut choices = snapshot
        .folders
        .iter()
        .map(|folder| Ok((path(&snapshot.folders, &folder.id)?, &folder.id)))
        .collect::<Result<Vec<_>>>()?;
    choices.sort();
    if choices.is_empty() {
        return Err("Workspace root folder not found. Initialize it in the web app first.".into());
    }
    let can_create = snapshot.role != "viewer" && !snapshot.rotation_required;
    let mut visible = choices.clone();
    loop {
        writeln!(
            output,
            "Choose a folder (type text to filter, / to reset, q to cancel):"
        )?;
        for (index, (folder_path, _)) in visible.iter().enumerate() {
            let label = if folder_path.is_empty() {
                "/ (root)"
            } else {
                folder_path
            };
            writeln!(output, "  {}. {label}", index + 1)?;
        }
        if can_create {
            writeln!(output, "  n. Create a new folder")?;
        } else if snapshot.rotation_required {
            writeln!(
                output,
                "Folder creation requires key rotation in workspace settings."
            )?;
        }
        let selected = prompt(input, output, "Folder number or search: ")?;
        if selected.eq_ignore_ascii_case("q") {
            return Err("Setup cancelled. Project configuration was not changed.".into());
        }
        if selected.eq_ignore_ascii_case("n") {
            if !can_create {
                writeln!(
                    output,
                    "Folder creation is unavailable. Choose an existing folder."
                )?;
                continue;
            }
            loop {
                let folder_path = prompt(
                    input,
                    output,
                    "New folder path (e.g. product:production; / to go back): ",
                )?;
                if folder_path == "/" {
                    break;
                }
                match validate_folder_path(&folder_path) {
                    Ok(()) => return Ok(FolderSelection::Create(folder_path)),
                    Err(error) => writeln!(output, "{error}")?,
                }
            }
        } else if selected == "/" {
            visible = choices.clone();
        } else if let Ok(number) = selected.parse::<usize>() {
            if let Some((_, id)) = number.checked_sub(1).and_then(|index| visible.get(index)) {
                return Ok(FolderSelection::Existing((*id).clone()));
            }
            writeln!(output, "Invalid folder selection. Choose a listed option.")?;
        } else {
            let query = selected.to_lowercase();
            let matches: Vec<_> = choices
                .iter()
                .filter(|(folder_path, _)| {
                    folder_path.to_lowercase().contains(&query)
                        || (folder_path.is_empty() && "root".contains(&query))
                })
                .cloned()
                .collect();
            if matches.is_empty() {
                writeln!(
                    output,
                    "No matching folders. Try another search or / to reset."
                )?;
            } else {
                visible = matches;
            }
        }
    }
}
pub(super) fn validate_folder_path(folder_path: &str) -> Result<()> {
    let parts: Vec<_> = folder_path.split(':').collect();
    if parts.len() > 63 {
        return Err("Folder nesting is too deep (maximum 63 levels).".into());
    }
    if parts.iter().any(|name| {
        name.trim().is_empty()
            || *name == "/"
            || name.encode_utf16().count() > 128
            || name.chars().any(|ch| ch <= '\u{1f}')
    }) {
        return Err("Use nonempty folder names of at most 128 characters, separated by colons, without control characters.".into());
    }
    Ok(())
}
pub(super) fn create_folder_path(
    snapshot: &mut Snapshot,
    org_key: &[u8],
    folder_path: &str,
) -> Result<String> {
    if snapshot.rotation_required {
        return Err("Workspace key rotation is required. Open workspace settings.".into());
    }
    if snapshot.role == "viewer" {
        return Err("Viewers cannot create folders".into());
    }
    validate_folder_path(folder_path)?;
    let mut folders = snapshot.folders.clone();
    let mut parent = folders
        .iter()
        .find(|folder| folder.parent_id.is_none())
        .ok_or("Workspace root folder not found. Initialize it in the web app first.")?
        .id
        .clone();
    for name in folder_path.split(':') {
        if let Some(folder) = folders.iter().find(|folder| {
            folder.parent_id.as_deref() == Some(parent.as_str()) && folder.name == name
        }) {
            parent = folder.id.clone();
            continue;
        }
        if folders.len() >= 2000 {
            return Err("Workspace folder limit reached (2000).".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut key = Zeroizing::new(vec![0u8; 32]);
        rand::rngs::OsRng.try_fill_bytes(&mut key)?;
        let wrapped_key = seal(
            org_key,
            &key,
            &context(json!([
                "folder",
                snapshot.organization_id,
                id,
                snapshot.epoch
            ])),
        )?;
        folders.push(Folder {
            id: id.clone(),
            parent_id: Some(parent),
            name: name.to_string(),
            wrapped_key,
        });
        parent = id;
    }
    snapshot.folders = folders;
    Ok(parent)
}
pub(super) async fn init(
    options: &Options,
    org: Option<String>,
    folder_path: Option<String>,
) -> Result<()> {
    if !options.interactive() && folder_path.is_none() {
        return Err(
            "Choose a folder with --path (use --path / for root), or run ve init in a terminal."
                .into(),
        );
    }
    let existing = find_project()?;
    let server = match &existing {
        Some(project) => project.server.clone(),
        None => validate_server(&get_base_url())?,
    };
    let root = env::current_dir()?;
    let credentials = match credentials_optional(&server)? {
        Some(credentials) => credentials,
        None if options.interactive() => {
            options.progress(&format!("Sign in to {server} to configure this project."));
            authenticate_for(options, &server).await?;
            credentials(&server)?
        }
        None => return Err("Authentication required. Run ve auth, then run ve init again.".into()),
    };
    let workspaces: Vec<Workspace> = serde_json::from_value(
        request(options, &server, &credentials, "/api/workspaces", None).await?,
    )?;
    let choices = workspace_choices(&workspaces, org.as_deref())?;
    if choices.len() > 1 && !options.interactive() {
        return Err("Multiple workspaces match. Pass --org with a unique workspace name or ID. Run ve workspaces to list them.".into());
    }
    let workspace = choose_workspace(&choices)?;
    let mut project = Project {
        server,
        organization_id: workspace.id.clone(),
        folder_id: String::new(),
        root,
    };
    let mut snapshot = snapshot(options, &project, &credentials).await?;
    let selection = if folder_path.is_none() && options.interactive() {
        choose_folder(&snapshot, &mut io::stdin().lock(), &mut io::stderr().lock())?
    } else {
        let folder_path = folder_path.as_deref().ok_or(
            "Choose a folder with --path (use --path / for root), or run ve init in a terminal.",
        )?;
        let folder_path = if folder_path == "/" { "" } else { folder_path };
        let folder = snapshot
            .folders
            .iter()
            .find(|folder| path(&snapshot.folders, &folder.id).ok().as_deref() == Some(folder_path))
            .ok_or("Folder not found. Run ve init without --path in a terminal to create it.")?;
        FolderSelection::Existing(folder.id.clone())
    };
    let original_folder_count = snapshot.folders.len();
    project.folder_id = match selection {
        FolderSelection::Existing(id) => id,
        FolderSelection::Create(folder_path) => {
            let org_key = organization_key(&snapshot, &credentials)?;
            create_folder_path(&mut snapshot, &org_key, &folder_path)?
        }
    };
    folder_key(&snapshot, &credentials, &project.folder_id)?;
    if snapshot.folders.len() != original_folder_count {
        let body = json!({"action":"save","revision":snapshot.revision,"epoch":snapshot.epoch,"folders":snapshot.folders,"secrets":snapshot.secrets});
        request(
            options,
            &project.server,
            &credentials,
            &format!("/api/workspaces/{}", project.organization_id),
            Some(body),
        )
        .await?;
    }
    let selected_path = path(&snapshot.folders, &project.folder_id)?;
    let mut file = tempfile::NamedTempFile::new_in(&project.root)?;
    file.write_all(serde_json::to_string_pretty(&project)?.as_bytes())?;
    file.persist(project.root.join(".voe.json"))?;
    let selected_path = if selected_path.is_empty() {
        "/"
    } else {
        &selected_path
    };
    let env_file = options.env_path(&project);
    let next_command = if options.file == std::path::Path::new(".env") {
        "ve pull".to_string()
    } else {
        format!(
            "ve --file {} pull",
            shell_quote(&options.file.to_string_lossy())
        )
    };
    options.emit(
        &json!({"configured": true, "server": project.server, "workspace": workspace.name, "organization_id": project.organization_id, "folder": selected_path, "folder_id": project.folder_id, "project_root": project.root, "file": env_file, "next_command": next_command}),
        &format!("Project configured: {} ({selected_path})\nFile: {}\nNext: {next_command}", workspace.name, env_file.display()),
    )
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "_./-".contains(ch))
        && !value.is_empty()
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_link_carries_exact_code_and_fingerprint() {
        let fingerprint = "a".repeat(64);
        let url = approval_url("https://env.voe.dk", "A B&C", &fingerprint).unwrap();
        assert_eq!(url.path(), "/device");
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["user_code"], "A B&C");
        assert_eq!(query["fingerprint"], fingerprint);
        assert_eq!(query.len(), 2);
    }

    #[test]
    fn workspace_picker_filters_and_retries_without_selecting_automatically() {
        let workspaces = [
            Workspace {
                id: "a".into(),
                name: "Wemuda".into(),
                role: "owner".into(),
            },
            Workspace {
                id: "b".into(),
                name: "Other".into(),
                role: "viewer".into(),
            },
        ];
        let choices: Vec<_> = workspaces.iter().collect();
        let mut output = Vec::new();
        let selected =
            choose_workspace_with_reader(&choices, &mut &b"missing\n0\nWEMU\n1\n"[..], &mut output)
                .unwrap();
        assert_eq!(selected.id, "a");
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("No matching workspaces"));
        assert!(output.contains("Invalid selection"));
        let selected =
            choose_workspace_with_reader(&choices, &mut &b"WEMU\n/\n2\n"[..], &mut Vec::new())
                .unwrap();
        assert_eq!(selected.id, "b");
        assert!(choose_workspace_with_reader(&choices, &mut &b"q\n"[..], &mut Vec::new()).is_err());
    }

    #[test]
    fn folder_picker_supports_search_reset_and_back_from_creation() {
        let snapshot = Snapshot {
            organization_id: "org".into(),
            epoch: 1,
            revision: 1,
            rotation_required: false,
            role: "owner".into(),
            folders: vec![
                Folder {
                    id: "root".into(),
                    parent_id: None,
                    name: "".into(),
                    wrapped_key: "".into(),
                },
                Folder {
                    id: "prod".into(),
                    parent_id: Some("root".into()),
                    name: "production".into(),
                    wrapped_key: "".into(),
                },
            ],
            secrets: vec![],
            envelopes: vec![],
        };
        let selected = choose_folder(&snapshot, &mut &b"PROD\n1\n"[..], &mut Vec::new()).unwrap();
        assert!(matches!(selected, FolderSelection::Existing(id) if id == "prod"));
        let selected =
            choose_folder(&snapshot, &mut &b"prod\n/\nn\n/\n1\n"[..], &mut Vec::new()).unwrap();
        assert!(matches!(selected, FolderSelection::Existing(id) if id == "root"));
        assert!(choose_folder(&snapshot, &mut &b"q\n"[..], &mut Vec::new()).is_err());
    }

    #[test]
    fn next_command_quotes_environment_file_paths() {
        assert_eq!(shell_quote(".env.local"), ".env.local");
        assert_eq!(shell_quote("project files/.env"), "'project files/.env'");
        assert_eq!(shell_quote("user's.env"), "'user'\"'\"'s.env'");
    }
}
