#!/bin/sh
set -eu

voe_url=${1:?Pass the VOE site URL.}
voe_url=${voe_url%/}
case "$(uname -s)" in
    Darwin) voe_os=darwin ;;
    Linux) voe_os=linux ;;
    *) printf '%s\n' 'Use the PowerShell installer on Windows.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) voe_arch=amd64 ;;
    arm64|aarch64) voe_arch=arm64 ;;
    *) printf '%s\n' 'Supported architectures are x86_64 and ARM64.' >&2; exit 1 ;;
esac

voe_download=$(mktemp)
trap 'rm -f "$voe_download"' 0
trap 'exit 1' HUP INT TERM
curl -fsSL "$voe_url/downloads/ve-$voe_os-$voe_arch" -o "$voe_download"
mkdir -p "$HOME/.local/bin" "$HOME/.voe"
install -m 755 "$voe_download" "$HOME/.local/bin/ve"
printf '%s\n' "$voe_url" > "$HOME/.voe/server-url"

voe_shell=${SHELL:-}
case "${voe_shell##*/}" in
    zsh) set -- "${ZDOTDIR:-$HOME}/.zshrc" ;;
    bash)
        if [ -f "$HOME/.bash_profile" ]; then
            set -- "$HOME/.bashrc" "$HOME/.bash_profile"
        else
            set -- "$HOME/.bashrc" "$HOME/.profile"
        fi ;;
    fish)
        mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d"
        printf '%s\n' "fish_add_path \"\$HOME/.local/bin\"" > "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/voe.fish"
        set -- ;;
    *) set -- "$HOME/.profile" ;;
esac
voe_path_line="export PATH=\"\$HOME/.local/bin:\$PATH\""
for voe_profile do
    mkdir -p "$(dirname "$voe_profile")"
    touch "$voe_profile"
    if ! grep -Fqx "$voe_path_line" "$voe_profile"; then
        printf '\n%s\n' "$voe_path_line" >> "$voe_profile"
    fi
done
printf '%s\n' 'Installed ve. Open a new terminal and run: ve auth'
