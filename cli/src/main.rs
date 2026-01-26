use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};

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
                        return Err(format!("Authorization failed: {}", 
                            error_data.error_description.unwrap_or(error_data.error)).into());
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = env::var("VOE_BASE_URL").unwrap_or_else(|_| "http://localhost:5173".to_string());

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
                test_api(&base_url, &new_token.access_token).await?;
            } else {
                return Err(e);
            }
        }
    }

    Ok(())
}
