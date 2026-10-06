use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn project() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::write(
        root.join(".voe.json"),
        json!({"server": "https://example.test", "organizationId": "workspace", "folderId": "root"}).to_string(),
    )
    .unwrap();
    (dir, root)
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ve"))
        .current_dir(root)
        .args(args)
        .env("VOE_BASE_URL", "invalid-origin")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn json_success(output: &Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_value_hidden(output: &Output, value: &str) {
    assert!(!String::from_utf8_lossy(&output.stdout).contains(value));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(value));
}

#[test]
fn validate_from_subdirectory_uses_project_relative_file_and_json_output() {
    let (_dir, root) = project();
    let child = root.join("src/components");
    fs::create_dir_all(&child).unwrap();
    fs::write(
        root.join(".env.local"),
        "TOKEN=private-value-123\nPORT=3100\n",
    )
    .unwrap();
    fs::write(child.join(".env.local"), "WRONG=directory\n").unwrap();

    let output = run(&child, &["validate", "--file", ".env.local", "--json"]);
    let value = json_success(&output);
    assert_eq!(
        Path::new(value["file"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        root.join(".env.local").canonicalize().unwrap()
    );
    assert_eq!(value["variables"], 2);
    assert_eq!(value["valid"], true);
    assert_value_hidden(&output, "private-value-123");
}

#[test]
fn validate_accepts_an_absolute_file_outside_the_project() {
    let (_dir, root) = project();
    let external = tempfile::tempdir().unwrap();
    let file = external.path().canonicalize().unwrap().join("custom.env");
    fs::write(&file, "EXTERNAL=private-external-value\n").unwrap();
    fs::write(root.join(".env"), "A=wrong\nB=wrong\n").unwrap();

    let output = run(
        &root,
        &["--file", file.to_str().unwrap(), "validate", "--json"],
    );
    let value = json_success(&output);
    assert_eq!(value["file"], file.to_str().unwrap());
    assert_eq!(value["variables"], 1);
    assert_value_hidden(&output, "private-external-value");
}

#[test]
fn invalid_dotenv_errors_are_json_and_never_echo_values() {
    let (_dir, root) = project();
    fs::write(
        root.join(".env"),
        "GOOD=private-valid-value\nBROKEN=\"private-invalid-value\n",
    )
    .unwrap();

    let output = run(&root, &["validate", "--json"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let value: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(value["error"].as_str().unwrap().contains(".env"));
    assert_value_hidden(&output, "private-valid-value");
    assert_value_hidden(&output, "private-invalid-value");
}

#[test]
fn quiet_suppresses_success_but_keeps_actionable_errors() {
    let (_dir, root) = project();
    fs::write(root.join(".env"), "TOKEN=private-quiet-value\n").unwrap();
    let output = run(&root, &["validate", "--quiet"]);
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    fs::remove_file(root.join(".env")).unwrap();
    let output = run(&root, &["validate", "--quiet"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("--file"));
    assert!(error.contains("ve pull"));
}

#[test]
fn noninteractive_init_requires_a_folder_before_accessing_server_or_credentials() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["init", "--no-input"],
        vec!["init", "--json"],
        vec!["init"],
    ] {
        let output = run(dir.path(), &args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("--path"), "{error}");
        assert!(!error.contains("invalid-origin"));
        assert!(!dir.path().join(".voe.json").exists());
    }
}

#[test]
fn force_and_conflict_policy_are_rejected_together_before_project_access() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(
        dir.path(),
        &["pull", "--force", "--conflicts", "use-remote"],
    );
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("--force"));
    assert!(error.contains("--conflicts"));
    assert!(error.contains("cannot be used with"));
}

#[test]
fn shell_completion_scripts_include_commands_and_conflict_policies() {
    let dir = tempfile::tempdir().unwrap();
    for shell in ["bash", "zsh", "fish"] {
        let output = run(dir.path(), &["completions", shell, "--json"]);
        let value = json_success(&output);
        assert_eq!(value["shell"], shell);
        let script = value["script"].as_str().unwrap();
        assert!(script.contains("status"));
        assert!(script.contains("dry-run"));
        assert!(script.contains("keep-local"));
        assert!(script.contains("use-remote"));
    }
}
