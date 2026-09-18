#!/bin/sh
# Install the tunneler CLI on macOS or Linux:
#
#   curl -fsSL https://raw.githubusercontent.com/mtsaas/tunneler/main/install.sh | sh
#
# Uses the Go toolchain if there is one, otherwise builds in Docker.
#   TUNNELER_VERSION      version to install (default: latest)
#   TUNNELER_INSTALL_DIR  where the Docker build puts the binary (default: ~/.local/bin)
set -eu

pkg="github.com/mtsaas/tunneler/cmd/tunneler@${TUNNELER_VERSION:-latest}"

if command -v go >/dev/null 2>&1; then
  echo "Installing with go..."
  go install "$pkg"
  dir="$(go env GOBIN)"
  [ -n "$dir" ] || dir="$(go env GOPATH)/bin"

elif command -v docker >/dev/null 2>&1; then
  case "$(uname -s)" in
    Darwin) os=darwin ;;
    Linux)  os=linux ;;
    *) echo "Unsupported system: $(uname -s)" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
  dir="${TUNNELER_INSTALL_DIR:-$HOME/.local/bin}"
  mkdir -p "$dir"
  echo "Building for $os/$arch in Docker..."
  # A cross-compiled "go install" lands in bin/<os>_<arch>/, a native one in bin/.
  docker run --rm -e GOOS="$os" -e GOARCH="$arch" -e CGO_ENABLED=0 -v "$dir:/out" golang:1.26 \
    sh -c "go install $pkg && cp \$(find /go/bin -type f -name tunneler) /out/tunneler"
  chmod +x "$dir/tunneler"

else
  echo "Install Go (https://go.dev/dl) or Docker (https://docs.docker.com/get-docker), then run this again." >&2
  exit 1
fi

echo "Installed: $dir/tunneler ($("$dir/tunneler" version 2>/dev/null | head -1 | sed 's/^client: *//'))"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$dir:\$PATH\"" ;;
esac
echo "Next:  tunneler config --server <coordinator URL>"
