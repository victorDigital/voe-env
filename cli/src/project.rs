use super::*;

pub(super) fn find_project_at(start: &Path) -> Result<Option<Project>> {
    for root in start.ancestors() {
        let config = root.join(".voe.json");
        let contents = match fs::read_to_string(&config) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!("Could not read {}: {error}", config.display()).into())
            }
        };
        let mut project: Project = serde_json::from_str(&contents).map_err(|error| {
            format!(
                "Invalid {}: {error}. Fix the configuration, or remove it and run ve init from its folder.",
                config.display()
            )
        })?;
        project.server = validate_server(&project.server)?;
        project.root = root.to_path_buf();
        return Ok(Some(project));
    }
    Ok(None)
}

pub(super) fn find_project() -> Result<Option<Project>> {
    find_project_at(&env::current_dir()?)
}

pub(super) fn project() -> Result<Project> {
    find_project()?.ok_or_else(|| {
        "No .voe.json found in this folder or its parents. Run ve init to connect this project."
            .into()
    })
}

pub(super) fn active_server() -> Result<String> {
    match find_project()? {
        Some(project) => Ok(project.server),
        None => validate_server(&get_base_url()),
    }
}

pub(super) fn credentials_optional(server: &str) -> Result<Option<Credentials>> {
    let Some(stored) = CredentialStore::new(server)?.load_optional()? else {
        return Ok(None);
    };
    let credentials: Credentials = serde_json::from_str(&stored)
        .map_err(|_| "Stored CLI credentials are invalid. Run ve auth to enroll again.")?;
    Ok((credentials.expires_at > now()).then_some(credentials))
}

pub(super) fn credentials(server: &str) -> Result<Credentials> {
    credentials_optional(server)?
        .ok_or_else(|| "No active CLI session for this server. Run ve auth to sign in.".into())
}

#[derive(Serialize)]
pub(super) struct ProjectContext {
    pub workspace: String,
    pub folder: String,
    pub server: String,
    pub file: String,
    pub role: String,
}

impl ProjectContext {
    pub fn display(&self) -> String {
        format!(
            "{} / {} → {}\nServer: {} · Role: {}",
            self.workspace, self.folder, self.file, self.server, self.role
        )
    }
}

pub(super) async fn load_context(
    project: &Project,
    snapshot: &Snapshot,
    options: &Options,
    credentials: &Credentials,
) -> Result<ProjectContext> {
    let workspaces: Vec<Workspace> = serde_json::from_value(
        request(
            options,
            &project.server,
            credentials,
            "/api/workspaces",
            None,
        )
        .await?,
    )?;
    let workspace = workspaces.iter().find(|workspace| workspace.id == project.organization_id)
        .ok_or("This workspace is no longer available. Run ve workspaces, then ve init to choose another.")?;
    let folder = path(&snapshot.folders, &project.folder_id)?;
    Ok(ProjectContext {
        workspace: workspace.name.clone(),
        folder: if folder.is_empty() {
            "/".into()
        } else {
            folder
        },
        server: project.server.clone(),
        file: options.env_path(project).display().to_string(),
        role: snapshot.role.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path, folder: &str) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join(".voe.json"),
            json!({"server":"https://example.test","organizationId":"org","folderId":folder})
                .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn nearest_project_owns_relative_environment_file() {
        let dir = tempfile::tempdir().unwrap();
        config(dir.path(), "outer");
        let nested = dir.path().join("app");
        config(&nested, "inner");
        let child = nested.join("src");
        fs::create_dir(&child).unwrap();
        let project = find_project_at(&child).unwrap().unwrap();
        assert_eq!(project.folder_id, "inner");
        let options = Options {
            file: ".env.local".into(),
            ..Default::default()
        };
        assert_eq!(options.env_path(&project), nested.join(".env.local"));
        assert!(serde_json::to_value(&project)
            .unwrap()
            .get("root")
            .is_none());
    }

    #[test]
    fn malformed_nearest_config_does_not_fall_back_to_parent() {
        let dir = tempfile::tempdir().unwrap();
        config(dir.path(), "outer");
        let nested = dir.path().join("app");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join(".voe.json"), "{").unwrap();
        assert!(find_project_at(&nested).is_err());
    }
}
