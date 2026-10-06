use super::*;

pub(super) async fn cmd_update(options: &Options) -> Result<()> {
    let (asset, header): (&str, &[u8]) = match (env::consts::OS, env::consts::ARCH) {
        ("macos", "x86_64") => ("ve-darwin-amd64", b"\xcf\xfa\xed\xfe"),
        ("macos", "aarch64") => ("ve-darwin-arm64", b"\xcf\xfa\xed\xfe"),
        ("linux", "x86_64") => ("ve-linux-amd64", b"\x7fELF"),
        ("linux", "aarch64") => ("ve-linux-arm64", b"\x7fELF"),
        ("windows", "x86_64") => ("ve-windows-amd64.exe", b"MZ"),
        ("windows", "aarch64") => ("ve-windows-arm64.exe", b"MZ"),
        _ => return Err("Updates are not supported on this platform".into()),
    };

    options.progress("Checking for updates...");
    let current_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
    let mut latest_version = None;
    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut url = reqwest::Url::parse(&format!("{}/downloads/{}", get_base_url(), asset))?;
    let mut redirects = 0;
    let mut response = loop {
        if let Some(version) = release_version(&url) {
            match version.cmp_precedence(&current_version) {
                std::cmp::Ordering::Equal => {
                    options.emit(
                        &json!({"updated":false,"version":current_version.to_string()}),
                        &format!("ve {current_version} is already up to date."),
                    )?;
                    return Ok(());
                }
                std::cmp::Ordering::Less => {
                    options.emit(&json!({"updated":false,"version":current_version.to_string(),"latestVersion":version.to_string()}), &format!("ve {current_version} is newer than the latest release ({version}). Keeping the installed version."))?;
                    return Ok(());
                }
                std::cmp::Ordering::Greater => latest_version = Some(version),
            }
        }
        let response = client.get(url.clone()).send().await?.error_for_status()?;
        if !response.status().is_redirection() {
            break response;
        }
        if redirects >= 10 {
            return Err("Too many redirects while checking for updates".into());
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or("Update redirect is missing its location")?
            .to_str()?;
        url = url.join(location)?;
        redirects += 1;
    };
    let length = response.content_length();
    let template = if length.is_some() {
        "Downloading [{bar:24}] {percent:>3}% {bytes}/{total_bytes}"
    } else {
        "Downloading {bytes}"
    };
    let progress = progress_bar(options, length, template)?;
    let mut binary = Vec::with_capacity(usize::try_from(length.unwrap_or(0))?);
    while let Some(chunk) = response.chunk().await? {
        binary.extend_from_slice(&chunk);
        progress.inc(chunk.len() as u64);
    }
    progress.finish_and_clear();

    if !binary.starts_with(header) {
        return Err("The download is not a valid executable for this platform".into());
    }
    if latest_version.is_none() && binary == fs::read(env::current_exe()?)? {
        options.emit(
            &json!({"updated":false,"version":current_version.to_string()}),
            &format!("ve {current_version} is already up to date."),
        )?;
        return Ok(());
    }

    let mut download = tempfile::NamedTempFile::new()?;
    download.write_all(&binary)?;
    download.flush()?;
    self_replace::self_replace(download.path())?;
    if let Some(version) = latest_version {
        options.emit(&json!({"updated":true,"previousVersion":current_version.to_string(),"version":version.to_string()}), &format!("Updated ve from {current_version} to {version}."))?;
    } else {
        options.emit(
            &json!({"updated":true,"previousVersion":current_version.to_string()}),
            "Updated ve.",
        )?;
    }
    Ok(())
}

fn release_version(url: &reqwest::Url) -> Option<semver::Version> {
    let segments: Vec<_> = url.path_segments()?.collect();
    let release = segments
        .windows(3)
        .find(|parts| parts[0] == "releases" && parts[1] == "download")?;
    semver::Version::parse(release[2].strip_prefix("cli-v")?).ok()
}
