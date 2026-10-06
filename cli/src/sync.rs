use super::*;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(super) enum ConflictPolicy {
    KeepLocal,
    UseRemote,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum PullMode {
    KeepLocal,
    UseRemote,
    Replace,
}

#[derive(Debug, Default, Serialize)]
struct Changes {
    added: Vec<String>,
    updated: Vec<String>,
    deleted: Vec<String>,
    unchanged: Vec<String>,
}

impl Changes {
    fn between(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Self {
        let mut changes = Self::default();
        for (key, value) in after {
            match before.get(key) {
                None => changes.added.push(key.clone()),
                Some(old) if old != value => changes.updated.push(key.clone()),
                Some(_) => changes.unchanged.push(key.clone()),
            }
        }
        changes.deleted = before
            .keys()
            .filter(|key| !after.contains_key(*key))
            .cloned()
            .collect();
        changes
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.updated.is_empty() && self.deleted.is_empty()
    }

    fn counts(&self) -> Value {
        json!({
            "added": self.added.len(), "updated": self.updated.len(),
            "deleted": self.deleted.len(), "unchanged": self.unchanged.len()
        })
    }

    fn summary(&self) -> String {
        format!(
            "{} added · {} updated · {} deleted · {} unchanged",
            self.added.len(),
            self.updated.len(),
            self.deleted.len(),
            self.unchanged.len()
        )
    }

    fn details(&self) -> String {
        let mut lines = Vec::new();
        for (label, keys) in [
            ("Add", &self.added),
            ("Update", &self.updated),
            ("Delete", &self.deleted),
        ] {
            if !keys.is_empty() {
                lines.push(format!("{label}: {}", keys.join(", ")));
            }
        }
        lines.join("\n")
    }
}

fn pull_values(
    local: &BTreeMap<String, String>,
    remote: &BTreeMap<String, String>,
    mode: PullMode,
) -> BTreeMap<String, String> {
    match mode {
        PullMode::Replace => remote.clone(),
        PullMode::UseRemote => {
            let mut values = local.clone();
            values.extend(remote.clone());
            values
        }
        PullMode::KeepLocal => {
            let mut values = remote.clone();
            values.extend(local.clone());
            values
        }
    }
}

fn choose_pull_mode(
    conflicts: &[String],
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<PullMode> {
    writeln!(output, "Differing keys: {}", conflicts.join(", "))?;
    writeln!(output, "  1. Keep local values; add remote-only keys")?;
    writeln!(output, "  2. Use remote values; keep local-only keys")?;
    writeln!(output, "  3. Replace everything; delete local-only keys")?;
    writeln!(output, "  q. Cancel")?;
    loop {
        write!(output, "Choose [1/2/3/q]: ")?;
        output.flush()?;
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Err("Pull cancelled. No local changes were made.".into());
        }
        match line.trim() {
            "1" => return Ok(PullMode::KeepLocal),
            "2" => return Ok(PullMode::UseRemote),
            "3" => return Ok(PullMode::Replace),
            "" | "q" | "Q" => return Err("Pull cancelled. No local changes were made.".into()),
            _ => writeln!(output, "Enter 1, 2, 3, or q.")?,
        }
    }
}

struct SyncReport<'a> {
    action: &'a str,
    dry_run: bool,
    changes: &'a Changes,
    message: &'a str,
    conflicts: &'a [String],
    needs_resolution: bool,
}

fn emit_sync(options: &Options, context: &ProjectContext, report: SyncReport<'_>) -> Result<()> {
    let SyncReport {
        action,
        dry_run,
        changes,
        message,
        conflicts,
        needs_resolution,
    } = report;
    let mut text = format!("{message}\n{}", changes.summary());
    let details = changes.details();
    if !details.is_empty() {
        text.push('\n');
        text.push_str(&details);
    }
    if needs_resolution {
        text.push_str(&format!(
            "\nDiffering keys: {}\nChoose --conflicts keep-local, --conflicts use-remote, or --force to replace everything.",
            conflicts.join(", ")
        ));
    }
    options.emit(
        &json!({
            "command": action, "context": context, "dryRun": dry_run,
            "counts": changes.counts(), "keys": changes, "message": message,
            "conflicts": conflicts, "needsResolution": needs_resolution
        }),
        &text,
    )
}

fn apply_push(
    snapshot: &mut Snapshot,
    folder_id: &str,
    key: &[u8],
    desired: &BTreeMap<String, String>,
    changes: &Changes,
) -> Result<()> {
    snapshot
        .secrets
        .retain(|secret| secret.folder_id != folder_id || desired.contains_key(&secret.name));
    for name in changes.added.iter().chain(&changes.updated) {
        let value = &desired[name];
        let id = snapshot
            .secrets
            .iter()
            .find(|secret| secret.folder_id == folder_id && secret.name == *name)
            .map(|secret| secret.id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let encrypted_value = seal(
            key,
            value.as_bytes(),
            &context(json!([
                "secret",
                snapshot.organization_id,
                folder_id,
                id,
                name,
                snapshot.epoch
            ])),
        )?;
        snapshot.secrets.retain(|secret| secret.id != id);
        snapshot.secrets.push(Secret {
            id,
            folder_id: folder_id.to_string(),
            name: name.clone(),
            encrypted_value,
        });
    }
    Ok(())
}

pub(super) async fn push(options: &Options, force: bool, dry_run: bool) -> Result<()> {
    let project = project()?;
    let env_path = options.env_path(&project);
    if !env_path.exists() {
        return Err(format!(
            "No environment file to push: {}. Create it or select one with --file.",
            env_path.display()
        )
        .into());
    }
    let values = local_values_at(&env_path)?;
    let credentials = credentials(&project.server)?;
    let mut snapshot = snapshot(options, &project, &credentials).await?;
    let project_context = load_context(&project, &snapshot, options, &credentials).await?;
    options.progress(&project_context.display());
    if snapshot.rotation_required {
        return Err("Workspace key rotation is required. Open workspace settings.".into());
    }
    if snapshot.role == "viewer" {
        return Err("Viewers cannot write secrets. Ask a workspace owner for write access.".into());
    }
    let remote = remote_values(&snapshot, &credentials, &project.folder_id)?;
    let desired = pull_values(
        &remote,
        &values,
        if force {
            PullMode::Replace
        } else {
            PullMode::UseRemote
        },
    );
    let changes = Changes::between(&remote, &desired);
    if dry_run || changes.is_empty() {
        return emit_sync(
            options,
            &project_context,
            SyncReport {
                action: "push",
                dry_run,
                changes: &changes,
                message: if changes.is_empty() {
                    "Already in sync."
                } else {
                    "Push preview; no changes made."
                },
                conflicts: &[],
                needs_resolution: false,
            },
        );
    }
    let key = folder_key(&snapshot, &credentials, &project.folder_id)?;
    apply_push(&mut snapshot, &project.folder_id, &key, &desired, &changes)?;
    let body = json!({"action":"save","revision":snapshot.revision,"epoch":snapshot.epoch,"folders":snapshot.folders,"secrets":snapshot.secrets});
    request(
        options,
        &project.server,
        &credentials,
        &format!("/api/workspaces/{}", project.organization_id),
        Some(body),
    )
    .await?;
    emit_sync(
        options,
        &project_context,
        SyncReport {
            action: "push",
            dry_run: false,
            changes: &changes,
            message: "Pushed encrypted secrets.",
            conflicts: &[],
            needs_resolution: false,
        },
    )
}

pub(super) async fn pull(
    options: &Options,
    force: bool,
    dry_run: bool,
    conflicts: Option<ConflictPolicy>,
) -> Result<()> {
    let project = project()?;
    let credentials = credentials(&project.server)?;
    let snapshot = snapshot(options, &project, &credentials).await?;
    let project_context = load_context(&project, &snapshot, options, &credentials).await?;
    options.progress(&project_context.display());
    let remote = remote_values(&snapshot, &credentials, &project.folder_id)?;
    let env_path = options.env_path(&project);
    let local = local_values_at(&env_path)?;
    let differing = Changes::between(&local, &remote).updated;
    let needs_resolution = !force && conflicts.is_none() && !differing.is_empty();
    let mode = if force {
        PullMode::Replace
    } else if let Some(policy) = conflicts {
        match policy {
            ConflictPolicy::KeepLocal => PullMode::KeepLocal,
            ConflictPolicy::UseRemote => PullMode::UseRemote,
        }
    } else if needs_resolution && !dry_run {
        if !options.interactive() {
            return Err(format!(
                "Differing keys: {}. Run ve pull --conflicts keep-local to keep local values, --conflicts use-remote to accept remote values, or --force to replace everything (deletes local-only keys).",
                differing.join(", ")
            ).into());
        }
        choose_pull_mode(
            &differing,
            &mut io::stdin().lock(),
            &mut io::stderr().lock(),
        )?
    } else {
        PullMode::UseRemote
    };
    let values = pull_values(&local, &remote, mode);
    let changes = Changes::between(&local, &values);
    if dry_run {
        return emit_sync(
            options,
            &project_context,
            SyncReport {
                action: "pull",
                dry_run: true,
                changes: &changes,
                message: if needs_resolution {
                    "Pull preview; resolve conflicts before applying."
                } else if !env_path.exists() {
                    "Pull preview; would create the local environment file."
                } else if changes.is_empty() && !differing.is_empty() {
                    "Pull preview; would keep local values without changing the file."
                } else if changes.is_empty() {
                    "Already in sync."
                } else {
                    "Pull preview; no changes made."
                },
                conflicts: &differing,
                needs_resolution,
            },
        );
    }
    let write_needed = !env_path.exists() || !changes.is_empty();
    if write_needed {
        write_env_at(&env_path, &values)?;
    }
    let message = if write_needed {
        "Pulled secrets into the local environment file."
    } else if !differing.is_empty() && mode == PullMode::KeepLocal {
        "Kept local values; no file changes needed."
    } else {
        "Already in sync."
    };
    emit_sync(
        options,
        &project_context,
        SyncReport {
            action: "pull",
            dry_run: false,
            changes: &changes,
            message,
            conflicts: &differing,
            needs_resolution: false,
        },
    )
}

pub(super) async fn inspect(options: &Options, command: &Commands) -> Result<()> {
    let project = project()?;
    let credentials = credentials(&project.server)?;
    let snapshot = snapshot(options, &project, &credentials).await?;
    let context = load_context(&project, &snapshot, options, &credentials).await?;
    match command {
        Commands::Diff { all } => {
            let local = local_values_at(&options.env_path(&project))?;
            let remote = remote_values(&snapshot, &credentials, &project.folder_id)?;
            let changes = Changes::between(&local, &remote);
            let mut entries = Vec::new();
            let mut text = context.display();
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
                if *all || status != "same" {
                    entries.push(json!({"name": key, "status": status}));
                    text.push_str(&format!("\n{status}: {key}"));
                }
            }
            if changes.is_empty() {
                text.push_str("\nAlready in sync.");
            }
            options.emit(
                &json!({"command": "diff", "context": context, "entries": entries,
                "counts": comparison_counts(&changes)}),
                &text,
            )
        }
        Commands::List => {
            let folders = snapshot
                .folders
                .iter()
                .map(|folder| {
                    Ok(json!({"id": folder.id, "path": path(&snapshot.folders, &folder.id)?}))
                })
                .collect::<Result<Vec<_>>>()?;
            let secrets = snapshot.secrets.iter().map(|secret| {
                Ok(json!({"name": secret.name, "folder": path(&snapshot.folders, &secret.folder_id)?}))
            }).collect::<Result<Vec<_>>>()?;
            options.emit(&json!({"command": "list", "context": context, "folders": folders, "secrets": secrets}),
                &format!("{}\n{}", context.display(), workspace_tree(&snapshot.folders, &snapshot.secrets)?))
        }
        Commands::Search { pattern } => {
            let pattern = pattern.to_lowercase();
            let mut matches = Vec::new();
            let mut lines = vec![context.display()];
            for secret in snapshot
                .secrets
                .iter()
                .filter(|s| s.name.to_lowercase().contains(&pattern))
            {
                let folder = path(&snapshot.folders, &secret.folder_id)?;
                lines.push(format!("{}:{}", folder, secret.name));
                matches.push(json!({"folder": folder, "name": secret.name}));
            }
            if matches.is_empty() {
                lines.push("No matching secret names.".into());
            }
            options.emit(
                &json!({"command": "search", "context": context, "matches": matches}),
                &lines.join("\n"),
            )
        }
        _ => Ok(()),
    }
}

fn comparison_counts(changes: &Changes) -> Value {
    json!({"remoteOnly": changes.added.len(), "localOnly": changes.deleted.len(),
        "differing": changes.updated.len(), "unchanged": changes.unchanged.len()})
}

pub(super) async fn status(options: &Options) -> Result<()> {
    let project = project()?;
    let file = options.env_path(&project);
    let credentials = match credentials(&project.server) {
        Ok(credentials) => credentials,
        Err(error) => {
            return options.emit(&json!({
                "command": "status", "authenticated": false, "authenticationError": error.to_string(),
                "project": {"workspaceId": project.organization_id, "folderId": project.folder_id,
                    "server": project.server, "file": file.display().to_string()}
            }), &format!(
                "Workspace ID: {}\nFolder ID: {}\nServer: {}\nFile: {}\nAuthentication unavailable: {error}",
                project.organization_id, project.folder_id, project.server, file.display()
            ));
        }
    };
    let snapshot = snapshot(options, &project, &credentials).await?;
    let context = load_context(&project, &snapshot, options, &credentials).await?;
    let local = local_values_at(&file)?;
    let remote = remote_values(&snapshot, &credentials, &project.folder_id)?;
    let changes = Changes::between(&local, &remote);
    let mut text = format!(
        "{}\nAuthentication: authenticated ({})\nLocal file: {}\n{} remote-only · {} local-only · {} differing · {} unchanged",
        context.display(), context.role,
        if file.exists() { "present" } else { "missing; run ve pull to create it" },
        changes.added.len(), changes.deleted.len(), changes.updated.len(), changes.unchanged.len()
    );
    if snapshot.rotation_required {
        text.push_str(
            "\nWorkspace key rotation is required. Open workspace settings before pushing.",
        );
    }
    options.emit(
        &json!({"command": "status", "context": context, "authenticated": true,
        "fileExists": file.exists(), "rotationRequired": snapshot.rotation_required,
        "counts": comparison_counts(&changes)}),
        &text,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn pull_policies_handle_conflicts_and_local_only_keys_explicitly() {
        let local = values(&[
            ("SAME", "same"),
            ("DIFFERENT", "local"),
            ("LOCAL", "private"),
        ]);
        let remote = values(&[
            ("SAME", "same"),
            ("DIFFERENT", "remote"),
            ("REMOTE", "private"),
        ]);
        let kept = pull_values(&local, &remote, PullMode::KeepLocal);
        assert_eq!(kept["DIFFERENT"], "local");
        assert!(kept.contains_key("LOCAL") && kept.contains_key("REMOTE"));
        let merged = pull_values(&local, &remote, PullMode::UseRemote);
        assert_eq!(merged["DIFFERENT"], "remote");
        assert!(merged.contains_key("LOCAL") && merged.contains_key("REMOTE"));
        assert_eq!(pull_values(&local, &remote, PullMode::Replace), remote);
        assert!(Changes::between(&local, &kept).updated.is_empty());
        assert_eq!(Changes::between(&local, &merged).updated, ["DIFFERENT"]);
        assert_eq!(Changes::between(&local, &remote).deleted, ["LOCAL"]);
    }

    #[test]
    fn summaries_include_only_key_names_and_accurate_counts() {
        let before = values(&[
            ("SAME", "hidden-a"),
            ("EDIT", "hidden-b"),
            ("DELETE", "hidden-c"),
        ]);
        let after = values(&[
            ("SAME", "hidden-a"),
            ("EDIT", "hidden-d"),
            ("ADD", "hidden-e"),
        ]);
        let changes = Changes::between(&before, &after);
        assert_eq!(
            changes.counts(),
            json!({"added": 1, "updated": 1, "deleted": 1, "unchanged": 1})
        );
        assert_eq!(changes.details(), "Add: ADD\nUpdate: EDIT\nDelete: DELETE");
        assert!(!serde_json::to_string(&changes).unwrap().contains("hidden-"));
        assert!(!changes.is_empty());
        assert!(Changes::between(&before, &before).is_empty());
    }

    #[test]
    fn force_push_empty_values_deletes_remote_keys_but_default_push_keeps_them() {
        let remote = values(&[("REMOTE", "private")]);
        let local = BTreeMap::new();
        assert!(
            Changes::between(&remote, &pull_values(&remote, &local, PullMode::UseRemote))
                .is_empty()
        );
        let replaced = pull_values(&remote, &local, PullMode::Replace);
        assert_eq!(Changes::between(&remote, &replaced).deleted, ["REMOTE"]);
    }

    #[test]
    fn push_preserves_unchanged_ciphertext_and_other_folders() {
        let secret = |id: &str, folder: &str, name: &str, ciphertext: &str| Secret {
            id: id.into(),
            folder_id: folder.into(),
            name: name.into(),
            encrypted_value: ciphertext.into(),
        };
        let mut snapshot = Snapshot {
            organization_id: "workspace".into(),
            epoch: 7,
            revision: 4,
            rotation_required: false,
            role: "owner".into(),
            folders: vec![],
            envelopes: vec![],
            secrets: vec![
                secret("same-id", "target", "SAME", "unchanged-ciphertext"),
                secret("edit-id", "target", "EDIT", "old-ciphertext"),
                secret("delete-id", "target", "DELETE", "deleted-ciphertext"),
                secret("other-id", "other", "EDIT", "other-folder-ciphertext"),
            ],
        };
        let before = values(&[("SAME", "same"), ("EDIT", "old"), ("DELETE", "removed")]);
        let after = values(&[("SAME", "same"), ("EDIT", "new"), ("ADD", "added")]);
        let key = [7; 32];
        apply_push(
            &mut snapshot,
            "target",
            &key,
            &after,
            &Changes::between(&before, &after),
        )
        .unwrap();
        assert_eq!(snapshot.secrets.len(), 4);
        assert_eq!(
            snapshot
                .secrets
                .iter()
                .find(|secret| secret.id == "same-id")
                .unwrap()
                .encrypted_value,
            "unchanged-ciphertext"
        );
        assert_eq!(
            snapshot
                .secrets
                .iter()
                .find(|secret| secret.id == "other-id")
                .unwrap()
                .encrypted_value,
            "other-folder-ciphertext"
        );
        assert!(!snapshot
            .secrets
            .iter()
            .any(|secret| secret.id == "delete-id"));
        for name in ["EDIT", "ADD"] {
            let secret = snapshot
                .secrets
                .iter()
                .find(|secret| secret.folder_id == "target" && secret.name == name)
                .unwrap();
            if name == "EDIT" {
                assert_eq!(secret.id, "edit-id");
            }
            let plaintext = unseal(
                &key,
                &secret.encrypted_value,
                &context(json!(["secret", "workspace", "target", secret.id, name, 7])),
            )
            .unwrap();
            assert_eq!(plaintext.as_slice(), after[name].as_bytes());
        }
        let original = serde_json::to_value(&snapshot).unwrap();
        apply_push(
            &mut snapshot,
            "target",
            &key,
            &after,
            &Changes::between(&after, &after),
        )
        .unwrap();
        assert_eq!(serde_json::to_value(&snapshot).unwrap(), original);
    }

    #[test]
    fn conflict_picker_retries_invalid_input_and_cancels_safely() {
        let conflicts = vec!["API_KEY".to_string()];
        for (input, expected) in [
            ("1\n", PullMode::KeepLocal),
            ("2\n", PullMode::UseRemote),
            ("3\n", PullMode::Replace),
        ] {
            assert_eq!(
                choose_pull_mode(&conflicts, &mut input.as_bytes(), &mut Vec::new()).unwrap(),
                expected
            );
        }
        let mut output = Vec::new();
        assert_eq!(
            choose_pull_mode(&conflicts, &mut &b"bad\n2\n"[..], &mut output).unwrap(),
            PullMode::UseRemote
        );
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("Enter 1, 2, 3, or q."));
        for input in ["", "\n", "q\n"] {
            assert!(choose_pull_mode(&conflicts, &mut input.as_bytes(), &mut Vec::new()).is_err());
        }
    }
}
