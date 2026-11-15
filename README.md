# iCreds CLI releases

Public distribution repository for iCreds CLI binaries. Application source and backend binaries are maintained separately.

## Downloads

Use [Releases](https://github.com/indyzai-p/icreds.cli-releases/releases) for Linux, macOS and Windows binaries on amd64 and arm64. Each release includes SHA256SUMS and shell/PowerShell installers. A release must be published before installation works.

## Installation

The [installer Gist](https://gist.github.com/indyzai-p/7ce9f34c72c7beba2d89aab7a16aaa97) contains installers for all supported platforms. Download and inspect the appropriate Raw script, then run:

Linux/macOS:

```sh
sh install.sh
```

Windows PowerShell:

```powershell
.\install.ps1
```

Installers detect your platform, download the latest stable release, verify its SHA-256 checksum, and install to your user `.local/bin` directory. Add that directory to PATH if needed. Set `ICREDS_VERSION` to pin a v-prefixed tag, or `ICREDS_INSTALL_DIR` to choose a different directory. No administrator privileges or GitHub token are required.

The CLI currently remains a scaffold placeholder. Checksums detect corruption; binaries are not independently signed.
