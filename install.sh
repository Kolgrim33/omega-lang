#!/usr/bin/env sh
# Omega installer — downloads the right prebuilt binary for your platform
# and installs it to /usr/local/bin (or ~/.local/bin as a fallback).
set -e

REPO="Kolgrim33/omega-lang"

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)
    case "$arch" in
      x86_64) asset="omega-linux-x86_64" ;;
      *) echo "No prebuilt binary for Linux $arch yet. Build from source instead: cargo install --path ." >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$arch" in
      arm64) asset="omega-macos-arm64" ;;
      x86_64) asset="omega-macos-x86_64" ;;
      *) echo "No prebuilt binary for macOS $arch yet." >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $os. Build from source instead: cargo install --path ." >&2
    exit 1
    ;;
esac

url="https://github.com/${REPO}/releases/latest/download/${asset}"
dest="/usr/local/bin/omega"

echo "Downloading omega for ${os}/${arch}..."

if [ -w "/usr/local/bin" ]; then
  curl -fsSL "$url" -o "$dest"
  chmod +x "$dest"
else
  sudo curl -fsSL "$url" -o "$dest"
  sudo chmod +x "$dest"
fi

echo "Installed to $dest"
omega --version 2>/dev/null || echo "Run 'omega <script.omg>' to get started."
