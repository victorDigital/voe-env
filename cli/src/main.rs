use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use pbkdf2::pbkdf2_hmac;
use reqwest::Client;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use tokio::time::{sleep, Duration};

#[derive(Parser)]
#[command(name = "ve")]
#[command(about = "VOE CLI - Environment Vault CLI", long_about = None)]
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
    Push,
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

fn get_token_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| env::var("USERPROFILE").unwrap_or_default());
    let mut path = PathBuf::from(home);
    path.push(".voe");
    path.push("token.json");
    path
}

fn load_token() -> Option<TokenStorage> {
    let path = get_token_path();
    if !path.exists() {
        return None;
    }

    match fs::read_to_string(&path) {
        Ok(content) => {
            match serde_json::from_str::<TokenStorage>(&content) {
                Ok(token) => {
                    // Check if token is expired
                    if let Some(expires_at) = token.expires_at {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if now >= expires_at {
                            return None; // Token expired
                        }
                    }
                    Some(token)
                }
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
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

fn get_base_url() -> String {
    env::var("VOE_BASE_URL").unwrap_or_else(|_| "http://localhost:5173".to_string())
}

async fn authenticate_device(base_url: &str) -> Result<TokenStorage, Box<dyn std::error::Error>> {
    let client = Client::new();

    // Step 1: Request device authorization
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

    // Step 2: Poll for authorization
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

            // Calculate expiration time
            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + tokens.expires_in;

            let token_storage = TokenStorage {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_at: Some(expires_at),
            };

            return Ok(token_storage);
        } else if verify_response.status() == 400 {
            // Parse error response
            if let Ok(error_data) = verify_response.json::<DeviceErrorResponse>().await {
                match error_data.error.as_str() {
                    "authorization_pending" => {
                        // Continue polling silently
                        continue;
                    }
                    "slow_down" => {
                        polling_interval += 5;
                        println!("⚠️  Slowing down polling to {}s", polling_interval);
                        continue;
                    }
                    "access_denied" => {
                        return Err("Access was denied by the user".into());
                    }
                    "expired_token" => {
                        return Err("The device code has expired. Please try again.".into());
                    }
                    _ => {
                        return Err(format!(
                            "Authorization failed: {}",
                            error_data.error_description.unwrap_or(error_data.error)
                        )
                        .into());
                    }
                }
            } else {
                // Still pending, continue
                continue;
            }
        } else {
            let error_text = verify_response.text().await?;
            return Err(format!("Authorization failed: {}", error_text).into());
        }
    }
}

async fn test_api(base_url: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    let response = client
        .get(&format!("{}/api/test", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if response.status().is_success() {
        let api_response: TestApiResponse = response.json().await?;
        println!("✅ API Test Successful!");
        if let Some(message) = api_response.message {
            println!("   {}", message);
        }
        if let Some(user) = api_response.user {
            println!("   User: {}", serde_json::to_string_pretty(&user)?);
        }
        Ok(())
    } else if response.status() == 401 {
        // Token is invalid, need to re-authenticate
        Err("Token is invalid or expired. Please login again.".into())
    } else {
        let error_text = response.text().await?;
        Err(format!("API call failed: {}", error_text).into())
    }
}

async fn cmd_auth() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = get_base_url();

    println!("🔑 Starting authentication...");
    let token = authenticate_device(&base_url).await?;
    save_token(&token)?;
    println!("💾 Token saved for future use");

    Ok(())
}

async fn cmd_test() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = get_base_url();

    // Try to load existing token
    let token_storage = match load_token() {
        Some(token) => {
            println!("📦 Using stored token");
            token
        }
        None => {
            println!("🔑 No valid token found, starting authentication...");
            let token = authenticate_device(&base_url).await?;
            save_token(&token)?;
            println!("💾 Token saved for future use");
            token
        }
    };

    // Test the API with the token
    match test_api(&base_url, &token_storage.access_token).await {
        Ok(_) => {
            // Token is valid, all good
            Ok(())
        }
        Err(e) => {
            // Token might be invalid, try to re-authenticate
            if e.to_string().contains("invalid") || e.to_string().contains("expired") {
                println!("⚠️  Token validation failed: {}", e);
                println!("🔄 Re-authenticating...");
                let new_token = authenticate_device(&base_url).await?;
                save_token(&new_token)?;
                println!("💾 New token saved");
                
                // Try API again with new token
                test_api(&base_url, &new_token.access_token).await
            } else {
                Err(e)
            }
        }
    }
}

fn cmd_init(path: Option<String>, password: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;
    let env_path = current_dir.join(".env");
    
    // Check if .env exists and contains VE_VAULT_KEYPASS
    if env_path.exists() {
        let env_content = fs::read_to_string(&env_path)?;
        if env_content.contains("VE_VAULT_KEYPASS=") {
            println!("ℹ️  This project already contains VOE configuration.");
            println!("   The .env file already has VE_VAULT_KEYPASS set.");
            println!("   If you want to update it, please edit the .env file manually.");
            return Ok(());
        }
    }
    
    // Get vault path
    let vault_path = match path {
        Some(p) => p,
        None => {
            print!("Enter vault path (e.g., org:product:dev): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };
    
    if vault_path.is_empty() {
        return Err("Vault path cannot be empty".into());
    }
    
    // Get vault password
    let vault_password = match password {
        Some(p) => p,
        None => {
            print!("Enter vault password: ");
            io::stdout().flush()?;
            read_password()?
        }
    };
    
    if vault_password.is_empty() {
        return Err("Vault password cannot be empty".into());
    }
    
    // Create the VE_VAULT_KEYPASS line
    let vault_line = format!("VE_VAULT_KEYPASS={};{}\n", vault_path, vault_password);
    
    // Read existing .env content if it exists
    let existing_content = if env_path.exists() {
        fs::read_to_string(&env_path)?
    } else {
        String::new()
    };
    
    // Write new content with VE_VAULT_KEYPASS at the top
    let mut new_content = vault_line;
    if !existing_content.is_empty() {
        // Only add a newline if existing content doesn't end with one
        if !existing_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(&existing_content);
    }
    
    fs::write(&env_path, new_content)?;
    
    println!("✅ VOE initialized successfully!");
    println!("   Vault path: {}", vault_path);
    println!("   Configuration saved to: {}", env_path.display());
    
    Ok(())
}

// Encryption functions matching the JavaScript implementation
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
    
    // Generate random IV (12 bytes for GCM)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Encrypt
    let ciphertext = cipher.encrypt(&nonce, text.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    // Combine IV and ciphertext (IV first, then ciphertext)
    let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
    combined.extend_from_slice(nonce.as_slice());
    combined.extend_from_slice(&ciphertext);
    
    // Base64 encode
    Ok(general_purpose::STANDARD.encode(&combined))
}

fn parse_env_file(env_path: &PathBuf) -> Result<(String, String), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(env_path)?;
    
    // Find VE_VAULT_KEYPASS line
    for line in content.lines() {
        if line.starts_with("VE_VAULT_KEYPASS=") {
            let value = line.strip_prefix("VE_VAULT_KEYPASS=").unwrap_or("");
            let parts: Vec<&str> = value.split(';').collect();
            if parts.len() >= 2 {
                return Ok((parts[0].to_string(), parts[1].to_string()));
            }
        }
    }
    
    Err("VE_VAULT_KEYPASS not found in .env file. Run 've init' first.".into())
}

fn parse_env_vars(env_path: &PathBuf) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let file = fs::File::open(env_path)?;
    let reader = io::BufReader::new(file);
    let mut vars = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        
        // Skip empty lines, comments, and VE_VAULT_KEYPASS
        if line.is_empty() || line.starts_with('#') || line.starts_with("VE_VAULT_KEYPASS=") {
            continue;
        }
        
        // Parse KEY=VALUE format
        if let Some(equal_pos) = line.find('=') {
            let key = line[..equal_pos].trim().to_string();
            let value = line[equal_pos + 1..].trim().to_string();
            
            // Remove quotes if present
            let value = value
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .map(|s| s.to_string())
                .unwrap_or(value);
            
            if !key.is_empty() {
                vars.push((key, value));
            }
        }
    }
    
    Ok(vars)
}

#[derive(Serialize)]
struct PushRequest {
    #[serde(rename = "vaultPath")]
    vault_path: String,
    envs: std::collections::HashMap<String, String>,
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

async fn cmd_push() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;
    let env_path = current_dir.join(".env");
    
    // Check if .env exists
    if !env_path.exists() {
        return Err(".env file not found. Run 've init' first.".into());
    }
    
    // Parse vault path and password from .env
    let (vault_path, vault_password) = parse_env_file(&env_path)?;
    
    // Parse env variables from .env
    let env_vars = parse_env_vars(&env_path)?;
    
    if env_vars.is_empty() {
        return Err("No environment variables found in .env file.".into());
    }
    
    println!("🔐 Encrypting {} environment variable(s)...", env_vars.len());
    
    // Encrypt each value
    let mut encrypted_envs = std::collections::HashMap::new();
    for (key, value) in &env_vars {
        match encrypt_value(value, &vault_password) {
            Ok(encrypted) => {
                encrypted_envs.insert(key.clone(), encrypted);
            }
            Err(e) => {
                eprintln!("⚠️  Failed to encrypt {}: {}", key, e);
            }
        }
    }
    
    if encrypted_envs.is_empty() {
        return Err("Failed to encrypt any environment variables.".into());
    }
    
    println!("📤 Uploading to vault: {}", vault_path);
    
    // Load token
    let token_storage = match load_token() {
        Some(token) => token,
        None => {
            println!("🔑 No valid token found, starting authentication...");
            let base_url = get_base_url();
            let token = authenticate_device(&base_url).await?;
            save_token(&token)?;
            token
        }
    };
    
    // Upload to API
    let base_url = get_base_url();
    let client = Client::new();
    
    let request = PushRequest {
        vault_path: vault_path.clone(),
        envs: encrypted_envs,
    };
    
    let response = client
        .post(&format!("{}/api/vault/push", base_url))
        .header("Authorization", format!("Bearer {}", token_storage.access_token))
        .json(&request)
        .send()
        .await?;
    
    if response.status().is_success() {
        let push_response: PushResponse = response.json().await?;
        println!("✅ {}", push_response.message.unwrap_or_else(|| "Upload successful!".to_string()));
        if let Some(success_count) = push_response.success_count {
            println!("   Successfully uploaded: {} variable(s)", success_count);
        }
        if let Some(error_count) = push_response.error_count {
            if error_count > 0 {
                println!("   Errors: {} variable(s)", error_count);
                if let Some(errors) = push_response.errors {
                    for error in errors {
                        println!("     - {}", error);
                    }
                }
            }
        }
        Ok(())
    } else if response.status() == 401 {
        // Token might be invalid, try to re-authenticate
        println!("⚠️  Token validation failed, re-authenticating...");
        let base_url = get_base_url();
        let new_token = authenticate_device(&base_url).await?;
        save_token(&new_token)?;
        
        // Retry upload
        let retry_response = client
            .post(&format!("{}/api/vault/push", base_url))
            .header("Authorization", format!("Bearer {}", new_token.access_token))
            .json(&request)
            .send()
            .await?;
        
        if retry_response.status().is_success() {
            let push_response: PushResponse = retry_response.json().await?;
            println!("✅ {}", push_response.message.unwrap_or_else(|| "Upload successful!".to_string()));
            Ok(())
        } else {
            let error_text = retry_response.text().await?;
            Err(format!("Upload failed: {}", error_text).into())
        }
    } else {
        let error_text = response.text().await?;
        Err(format!("Upload failed: {}", error_text).into())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Auth => cmd_auth().await,
        Commands::Test => cmd_test().await,
        Commands::Init { path, password } => cmd_init(path.clone(), password.clone()),
        Commands::Push => cmd_push().await,
    }
}
