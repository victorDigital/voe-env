use aes_gcm::{
    aead::{Aead, AeadCore},
    Aes256Gcm, KeyInit,
};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use reqwest::Client;
use rpassword;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Parser)]
#[command(name = "ve")]
#[command(about = "VOE ENV CLI for managing environment variables")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with the VOE server
    Auth,
    /// Test the protected API endpoint
    Test,
    /// Initialize VOE in the current directory
    Init {
        /// Vault path (e.g., org:product:dev)
        #[arg(short, long)]
        path: Option<String>,
        /// Vault password/lock
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Push .env file to the online vault
    Push {
        /// Force push - delete server variables not present locally
        #[arg(long)]
        force: bool,
    },
    /// Pull .env file from the online vault
    Pull {
        /// Force replace with server version, may delete unsynced variables
        #[arg(long)]
        force: bool,
        /// Vault path (e.g., org:product:dev) - initializes if .env doesn't exist
        #[arg(short, long)]
        path: Option<String>,
        /// Vault password/lock - initializes if .env doesn't exist
        #[arg(short = 'P', long)]
        password: Option<String>,
    },
    /// Change vault password (only if local and server are identical)
    ChangePassword {
        /// New vault password/lock
        #[arg(short = 'P', long)]
        password: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct DeviceAuthRequest {
    client_id: String,
}

#[derive(Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

#[derive(Serialize)]
struct DeviceVerifyRequest {
    grant_type: String,
    device_code: String,
    client_id: String,
}

#[derive(Deserialize)]
struct DeviceVerifyResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

#[derive(Deserialize)]
struct DeviceErrorResponse {
    error: String,
    error_description: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TokenStorage {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>, // Unix timestamp
}

#[derive(Deserialize)]
struct TestApiResponse {
    success: bool,
    message: Option<String>,
    user: Option<serde_json::Value>,
    error: Option<String>,
}

#[derive(Serialize)]
struct PushRequest {
    #[serde(rename = "vaultPath")]
    vault_path: String,
    envs: HashMap<String, String>,
}

#[derive(Deserialize)]
struct PushResponse {
    success: bool,
    message: Option<String>,
    #[serde(rename = "successCount")]
    success_count: Option<u32>,
    #[serde(rename = "errorCount")]
    error_count: Option<u32>,
    errors: Option<Vec<String>>,
    error: Option<String>,
}

#[derive(Serialize)]
struct PullRequest {
    #[serde(rename = "vaultPath")]
    vault_path: String,
}

#[derive(Deserialize)]
struct PullResponse {
    success: bool,
    message: Option<String>,
    envs: Option<HashMap<String, String>>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct DeleteResponse {
    success: bool,
    message: Option<String>,
    #[serde(rename = "deletedCount")]
    deleted_count: Option<u32>,
    #[serde(rename = "errorCount")]
    error_count: Option<u32>,
    errors: Option<Vec<String>>,
    error: Option<String>,
}

// Helper functions

fn get_token_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| env::var("USERPROFILE").unwrap_or_default());
    PathBuf::from(home).join(".voe").join("token.json")
}

fn load_token() -> Option<TokenStorage> {
    let path = get_token_path();
    if !path.exists() {
        return None;
    }
    fs::read_to_string(&path)
        .ok()
        .and_then(|content| serde_json::from_str::<TokenStorage>(&content).ok())
        .filter(|token| {
            if let Some(expires_at) = token.expires_at {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                now < expires_at
            } else {
                true
            }
        })
}

fn save_token(token: &TokenStorage) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(token)?;
    fs::write(&path, json)?;
    Ok(())
}

async fn authenticate_device(base_url: &str) -> Result<TokenStorage, Box<dyn std::error::Error>> {
    let client = Client::new();
    let device_req = DeviceAuthRequest {
        client_id: "voe-cli".to_string(),
    };

    let response: DeviceAuthResponse = client
        .post(&format!("{}/api/auth/device/code", base_url))
        .json(&device_req)
        .send()
        .await?
        .json()
        .await?;

    let verification_url = format!("{}/device?user_code={}", base_url, response.user_code);
    println!("🔐 Device Authorization Required");
    println!("Please visit: {}", verification_url);
    println!("Enter code: {}", response.user_code);
    println!("Waiting for authorization...");

    let verify_req = DeviceVerifyRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        device_code: response.device_code.clone(),
        client_id: "voe-cli".to_string(),
    };

    let mut polling_interval = response.interval;
    loop {
        sleep(Duration::from_secs(polling_interval)).await;
        let verify_response = client
            .post(&format!("{}/api/auth/device/token", base_url))
            .json(&verify_req)
            .send()
            .await?;

        if verify_response.status().is_success() {
            let tokens: DeviceVerifyResponse = verify_response.json().await?;
            println!("✅ Authorization successful!");
            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + tokens.expires_in;
            return Ok(TokenStorage {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_at: Some(expires_at),
            });
        } else if verify_response.status() == 400 {
            if let Ok(error_data) = verify_response.json::<DeviceErrorResponse>().await {
                match error_data.error.as_str() {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        polling_interval += 5;
                        println!("⚠️  Slowing down polling to {}s", polling_interval);
                        continue;
                    }
                    "access_denied" => return Err("Access was denied by the user".into()),
                    "expired_token" => {
                        return Err("The device code has expired. Please try again.".into())
                    }
                    _ => {
                        return Err(format!(
                            "Authorization failed: {}",
                            error_data.error_description.unwrap_or(error_data.error)
                        )
                        .into())
                    }
                }
            }
        } else {
            let error_text = verify_response.text().await?;
            return Err(format!("Authorization failed: {}", error_text).into());
        }
    }
}

async fn get_or_authenticate_token() -> Result<TokenStorage, Box<dyn std::error::Error>> {
    if let Some(token) = load_token() {
        return Ok(token);
    }
    println!("🔑 No valid token found, starting authentication...");
    let base_url = get_base_url();
    let token = authenticate_device(&base_url).await?;
    save_token(&token)?;
    println!("💾 Token saved for future use");
    Ok(token)
}

fn get_base_url() -> String {
    env::var("VOE_BASE_URL").unwrap_or_else(|_| "http://localhost:5173".to_string())
}

async fn make_authenticated_request<T: Serialize, R: for<'de> Deserialize<'de>>(
    method: reqwest::Method,
    url: &str,
    body: Option<&T>,
) -> Result<R, Box<dyn std::error::Error>> {
    let mut token = get_or_authenticate_token().await?;
    let client = Client::new();
    let mut request = client
        .request(method.clone(), url)
        .header("Authorization", format!("Bearer {}", token.access_token));
    if let Some(b) = body {
        request = request.json(b);
    }

    let mut response = request.send().await?;
    if response.status() == 401 {
        println!("⚠️  Token validation failed, re-authenticating...");
        let base_url = get_base_url();
        token = authenticate_device(&base_url).await?;
        save_token(&token)?;
        let mut retry_request = client
            .request(method, url)
            .header("Authorization", format!("Bearer {}", token.access_token));
        if let Some(b) = body {
            retry_request = retry_request.json(b);
        }
        response = retry_request.send().await?;
    }

    if response.status().is_success() {
        Ok(response.json().await?)
    } else {
        Err(format!("Request failed: {}", response.text().await?).into())
    }
}

async fn test_api() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = get_base_url();
    let api_response: TestApiResponse = make_authenticated_request(
        reqwest::Method::GET,
        &format!("{}/api/test", base_url),
        None::<&()>,
    )
    .await?;
    println!("✅ API Test Successful!");
    if let Some(message) = api_response.message {
        println!("   {}", message);
    }
    if let Some(user) = api_response.user {
        println!("   User: {}", serde_json::to_string_pretty(&user)?);
    }
    Ok(())
}

fn derive_key(password: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let salt = b"fixedsalt";
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100000, &mut key_bytes);
    Ok(key_bytes)
}

fn encrypt_value(text: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key_bytes = derive_key(password)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, text.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    let mut combined = nonce.to_vec();
    combined.extend(ciphertext);
    Ok(general_purpose::STANDARD.encode(&combined))
}

fn decrypt_value(
    encrypted_text: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let key_bytes = derive_key(password)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;
    let combined = general_purpose::STANDARD.decode(encrypted_text)?;
    if combined.len() < 12 {
        return Err("Invalid encrypted data: too short".into());
    }
    let nonce = &combined[..12];
    let ciphertext = &combined[12..];
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    String::from_utf8(plaintext)
        .map_err(|e| format!("Invalid UTF-8 in decrypted data: {}", e).into())
}

fn parse_env_file(env_path: &Path) -> Result<(String, String), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(env_path)?;
    for line in content.lines() {
        if line.starts_with("VE_VAULT_KEYPASS=") {
            let value = line
                .strip_prefix("VE_VAULT_KEYPASS=")
                .unwrap_or("")
                .split('#')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            let parts: Vec<&str> = if value.contains('+') {
                value.split('+').collect()
            } else {
                value.split(';').collect()
            };
            if parts.len() >= 2 {
                return Ok((parts[0].to_string(), parts[1].to_string()));
            }
        }
    }
    Err("VE_VAULT_KEYPASS not found in .env file. Run 've init' first.".into())
}

fn parse_env_vars(env_path: &Path) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let file = fs::File::open(env_path)?;
    let reader = BufReader::new(file);
    let mut vars = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("VE_VAULT_KEYPASS=") {
            continue;
        }
        if let Some(equal_pos) = line.find('=') {
            let key = line[..equal_pos].trim().to_string();
            let value_str = line[equal_pos + 1..].trim();
            let value = if value_str.starts_with('"') && value_str.ends_with('"') {
                value_str[1..value_str.len() - 1].to_string()
            } else if value_str.starts_with('\'') && value_str.ends_with('\'') {
                value_str[1..value_str.len() - 1].to_string()
            } else {
                value_str.to_string()
            };
            if !key.is_empty() {
                vars.push((key, value));
            }
        }
    }
    Ok(vars)
}

fn format_env_content(
    vault_path: &str,
    vault_password: &str,
    env_vars: &HashMap<String, String>,
) -> String {
    let mut content = format!(
        "VE_VAULT_KEYPASS={}+{} # automatically added by vault\n\n",
        vault_path, vault_password
    );
    let mut sorted_vars: Vec<_> = env_vars.iter().collect();
    sorted_vars.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in sorted_vars {
        content.push_str(&format!("{}={}\n", key, value));
    }
    content
}

fn write_env_file(
    env_path: &Path,
    vault_path: &str,
    vault_password: &str,
    env_vars: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = format_env_content(vault_path, vault_password, env_vars);
    fs::write(env_path, content)?;
    Ok(())
}

fn update_env_example(
    env_vars: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;
    let example_path = current_dir.join(".env.example");
    if !example_path.exists() {
        return Ok(());
    }
    let existing_content = fs::read_to_string(&example_path)?;
    let mut example_lines = Vec::new();
    let mut existing_keys = std::collections::HashSet::new();
    for line in existing_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            example_lines.push(line.to_string());
        } else if trimmed.starts_with('#') {
            example_lines.push(line.to_string());
        } else if let Some(equal_pos) = trimmed.find('=') {
            let key = trimmed[..equal_pos].trim().to_string();
            existing_keys.insert(key.clone());
            example_lines.push(format!("{}=xxx", key));
        } else {
            example_lines.push(line.to_string());
        }
    }
    let mut new_keys: Vec<String> = env_vars
        .keys()
        .filter(|k| !existing_keys.contains(*k))
        .cloned()
        .collect();
    new_keys.sort();
    if !new_keys.is_empty() {
        if !example_lines.is_empty() && !example_lines.last().unwrap().is_empty() {
            example_lines.push(String::new());
        }
        for key in new_keys {
            example_lines.push(format!("{}=xxx", key));
        }
    }
    let new_content = example_lines.join("\n");
    fs::write(&example_path, new_content)?;
    Ok(())
}

fn get_env_path() -> PathBuf {
    env::current_dir().unwrap().join(".env")
}

fn prompt_input(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn read_password() -> Result<String, Box<dyn std::error::Error>> {
    rpassword::read_password().map_err(|e| e.into())
}

fn encrypt_env_vars(
    env_vars: &[(String, String)],
    password: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut encrypted = HashMap::new();
    for (key, value) in env_vars {
        encrypted.insert(key.clone(), encrypt_value(value, password)?);
    }
    Ok(encrypted)
}

fn decrypt_env_vars(
    encrypted_envs: &HashMap<String, String>,
    password: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut decrypted = HashMap::new();
    for (key, encrypted_value) in encrypted_envs {
        decrypted.insert(key.clone(), decrypt_value(encrypted_value, password)?);
    }
    Ok(decrypted)
}

// Command functions

async fn cmd_auth() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 Starting authentication...");
    let base_url = get_base_url();
    let token = authenticate_device(&base_url).await?;
    save_token(&token)?;
    println!("💾 Token saved for future use");
    Ok(())
}

async fn cmd_test() -> Result<(), Box<dyn std::error::Error>> {
    test_api().await
}

fn cmd_init(
    path: Option<String>,
    password: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let env_path = get_env_path();
    if env_path.exists() {
        let content = fs::read_to_string(&env_path)?;
        if content.contains("VE_VAULT_KEYPASS=") {
            println!("ℹ️  This project already contains VOE configuration.");
            return Ok(());
        }
    }

    let vault_path =
        path.unwrap_or_else(|| prompt_input("Enter vault path (e.g., org:product:dev): ").unwrap());
    if vault_path.is_empty() {
        return Err("Vault path cannot be empty".into());
    }

    let vault_password = password.unwrap_or_else(|| read_password().unwrap());
    if vault_password.is_empty() {
        return Err("Vault password cannot be empty".into());
    }

    let existing_vars = if env_path.exists() {
        parse_env_vars(&env_path).unwrap_or_default()
    } else {
        Vec::new()
    };
    let env_vars: HashMap<String, String> = existing_vars.into_iter().collect();

    write_env_file(&env_path, &vault_path, &vault_password, &env_vars)?;
    update_env_example(&env_vars)?;

    println!("✅ VOE initialized successfully!");
    println!("   Vault path: {}", vault_path);
    Ok(())
}

async fn cmd_push(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let env_path = get_env_path();
    if !env_path.exists() {
        return Err(".env file not found. Run 've init' first.".into());
    }

    let (vault_path, vault_password) = parse_env_file(&env_path)?;
    let env_vars = parse_env_vars(&env_path)?;
    if env_vars.is_empty() {
        return Err("No environment variables found in .env file.".into());
    }

    if force {
        handle_force_push(&vault_path, &vault_password, &env_vars).await?;
    }

    println!(
        "🔐 Encrypting {} environment variable(s)...",
        env_vars.len()
    );
    let encrypted_envs = encrypt_env_vars(&env_vars, &vault_password)?;
    if encrypted_envs.is_empty() {
        return Err("Failed to encrypt any environment variables.".into());
    }

    println!("📤 Uploading to vault: {}", vault_path);
    let request = PushRequest {
        vault_path,
        envs: encrypted_envs,
    };
    let base_url = get_base_url();
    let response: PushResponse = make_authenticated_request(
        reqwest::Method::POST,
        &format!("{}/api/vault/push", base_url),
        Some(&request),
    )
    .await?;

    println!(
        "✅ {}",
        response
            .message
            .unwrap_or_else(|| "Upload successful!".to_string())
    );
    if let Some(success_count) = response.success_count {
        println!("   Successfully uploaded: {} variable(s)", success_count);
    }
    if let Some(error_count) = response.error_count {
        if error_count > 0 {
            println!("   Errors: {} variable(s)", error_count);
            if let Some(errors) = response.errors {
                for error in errors {
                    println!("     - {}", error);
                }
            }
        }
    }
    Ok(())
}

async fn handle_force_push(
    vault_path: &str,
    vault_password: &str,
    local_vars: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Checking for variables to delete on server...");
    let base_url = get_base_url();
    let response: PullResponse = make_authenticated_request(
        reqwest::Method::GET,
        &format!("{}/api/vault/pull?vaultPath={}", base_url, vault_path),
        None::<&PullRequest>,
    )
    .await?;

    if let Some(encrypted_server_envs) = response.envs {
        let server_vars = decrypt_env_vars(&encrypted_server_envs, vault_password)?;
        let local_keys: std::collections::HashSet<String> =
            local_vars.iter().map(|(k, _)| k.clone()).collect();
        let keys_to_delete: Vec<String> = server_vars
            .keys()
            .filter(|k| !local_keys.contains(*k))
            .cloned()
            .collect();

        if !keys_to_delete.is_empty() {
            println!("⚠️  Force mode: The following variables will be permanently deleted from the server:");
            for key in &keys_to_delete {
                println!("   - {}", key);
            }
            println!();
            if !prompt_input("This action is immediate and cannot be undone. Continue? (y/N): ")?
                .to_lowercase()
                .starts_with('y')
            {
                return Err("Operation cancelled.".into());
            }

            let delete_request =
                serde_json::json!({ "vaultPath": vault_path, "keys": keys_to_delete });
            let _: serde_json::Value = make_authenticated_request(
                reqwest::Method::DELETE,
                &format!("{}/api/vault/delete", base_url),
                Some(&delete_request),
            )
            .await?;
            println!("🗑️  Deleted variable(s) from server");
        } else {
            println!("✅ No variables to delete on server");
        }
    }
    Ok(())
}

async fn cmd_pull(
    force: bool,
    path: Option<String>,
    password: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let env_path = get_env_path();
    if !env_path.exists() {
        if let (Some(vault_path), Some(vault_password)) = (path, password) {
            cmd_init(Some(vault_path), Some(vault_password))?;
        } else {
            return Err(
                ".env file not found. Run 've init' first or provide -p and -P to initialize."
                    .into(),
            );
        }
    }

    let (vault_path, vault_password) = parse_env_file(&env_path)?;
    println!("📥 Pulling from vault: {}", vault_path);

    let base_url = get_base_url();
    let response: PullResponse = make_authenticated_request(
        reqwest::Method::GET,
        &format!("{}/api/vault/pull?vaultPath={}", base_url, vault_path),
        None::<&PullRequest>,
    )
    .await?;

    if let Some(encrypted_envs) = response.envs {
        println!(
            "🔓 Decrypting {} environment variable(s)...",
            encrypted_envs.len()
        );
        let decrypted_envs = decrypt_env_vars(&encrypted_envs, &vault_password)?;

        let local_vars = parse_env_vars(&env_path).unwrap_or_default();
        let final_vars = if force {
            println!("⚠️  Force mode: replacing local .env with server version");
            decrypted_envs
        } else {
            println!("🔄 Update mode: merging with local .env");
            let mut merged: HashMap<String, String> = local_vars.into_iter().collect();
            merged.extend(decrypted_envs);
            merged
        };

        write_env_file(&env_path, &vault_path, &vault_password, &final_vars)?;
        update_env_example(&final_vars)?;
        println!("✅ Pulled {} variable(s) from vault", final_vars.len());
        Ok(())
    } else {
        Err("No environment variables received from server".into())
    }
}

async fn cmd_change_password(
    new_password: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let env_path = get_env_path();
    if !env_path.exists() {
        return Err(".env file not found. Run 've init' first.".into());
    }

    let (vault_path, current_password) = parse_env_file(&env_path)?;
    let local_vars_vec = parse_env_vars(&env_path)?;
    if local_vars_vec.is_empty() {
        return Err("No environment variables found in .env file.".into());
    }

    println!("🔐 Checking vault synchronization: {}", vault_path);
    let base_url = get_base_url();
    let response: PullResponse = make_authenticated_request(
        reqwest::Method::GET,
        &format!("{}/api/vault/pull?vaultPath={}", base_url, vault_path),
        None::<&PullRequest>,
    )
    .await?;

    if let Some(encrypted_envs) = response.envs {
        let server_vars = decrypt_env_vars(&encrypted_envs, &current_password)?;
        let local_map: HashMap<String, String> = local_vars_vec.iter().cloned().collect();
        if local_map != server_vars {
            return Err("Local and server environments are not identical. Please sync before changing password.".into());
        }

        println!("✅ Environments are synchronized");
        let new_password = new_password.unwrap_or_else(|| read_password().unwrap());
        if new_password.is_empty() {
            return Err("New password cannot be empty".into());
        }

        println!("🔐 Re-encrypting with new password...");
        let re_encrypted_envs = encrypt_env_vars(&local_vars_vec, &new_password)?;

        write_env_file(&env_path, &vault_path, &new_password, &local_map)?;
        update_env_example(&local_map)?;

        println!("📤 Uploading with new encryption...");
        let request = PushRequest {
            vault_path,
            envs: re_encrypted_envs,
        };
        let _: PushResponse = make_authenticated_request(
            reqwest::Method::POST,
            &format!("{}/api/vault/push", base_url),
            Some(&request),
        )
        .await?;

        println!("✅ Password changed successfully!");
        Ok(())
    } else {
        Err("No environment variables found on server".into())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Auth => cmd_auth().await,
        Commands::Test => cmd_test().await,
        Commands::Init { path, password } => cmd_init(path.clone(), password.clone()),
        Commands::Push { force } => cmd_push(*force).await,
        Commands::Pull {
            force,
            path,
            password,
        } => cmd_pull(*force, path.clone(), password.clone()).await,
        Commands::ChangePassword { password } => cmd_change_password(password.clone()).await,
    }
}
