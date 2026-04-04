# ende

`ende` is a Go CLI for secure developer-to-developer secret exchange using:
- recipient public-key encryption (`age` / X25519)
- sender authentication (Ed25519 signature)
- local trust root (pinned keyring)
- trusted sender pinning (`sender_key_id` + signing public key)

## Security model
- A encrypts to B's recipient key -> B can decrypt.
- C cannot decrypt without matching private key.
- Signed envelopes detect tampering and sender spoofing.
- Plaintext output to stdout is blocked by default unless `--out -` is explicitly passed.

## Install/build
```bash
go build ./cmd/ende
```

## Install with Homebrew (tap)
```bash
brew tap DevopsArtFactory/ende https://github.com/DevopsArtFactory/homebrew-ende
brew install ende
```

Upgrade:
```bash
brew update
brew upgrade ende
```

Verify:
```bash
ende --version
```

## Install from GitHub Release (Linux / Windows)
Replace `vX.Y.Z` with the release tag.

Linux (auto-detect architecture):
```bash
VERSION=vX.Y.Z
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac
curl -fL "https://github.com/DevopsArtFactory/ende/releases/download/${VERSION}/ende-linux-${ARCH}" -o ende
chmod +x ende
sudo mv ende /usr/local/bin/ende
ende --version
```

Windows (auto-detect architecture, PowerShell):
```powershell
$Version = "vX.Y.Z"
$ArchRaw = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLower()
switch ($ArchRaw) {
  "x64" { $Arch = "amd64" }
  "arm64" { $Arch = "arm64" }
  default { throw "Unsupported arch: $ArchRaw" }
}
Invoke-WebRequest -Uri "https://github.com/DevopsArtFactory/ende/releases/download/$Version/ende-windows-$Arch.exe" -OutFile "ende.exe"
.\ende.exe --version
```

## Docker build
Build with containerized Go toolchain (host env independent):
```bash
make vendor
make docker-test
make docker-build
make docker-build-all
```
You can pin image:
```bash
make docker-build-all GO_DOCKER_IMAGE=golang:1.25
```

## Interactive Tutorial

New to ende? Run the built-in tutorial for a step-by-step walkthrough:

```bash
ende tutorial
```

The tutorial guides you through:
1. **Language selection** (English / Korean)
2. **Key generation** — creates your sender key pair
3. **Peer registration** — paste a peer's share token, or generate a local test key
4. **Encrypt** — interactive secret input (masked) with password policy guidance
5. **Decrypt** — automatically decrypts the result from step 4

## Quickstart
1. Generate local key material:
```bash
./ende key keygen --name alice --export-public --export-dir .
./ende key keygen --name bob --export-public --export-dir .
```

2. Alice shares `share:` token from keygen output to Bob.

You can re-print a share token later:
```bash
./ende key share --name alice
```

3. Bob registers interactively in one command (recipient + sender):
```bash
./ende register
# share token (ENDE-PUB-1:...): ENDE-PUB-1:...
# alias override (optional, Enter to use token id):
```

4. Run a local safety check before first real use:
```bash
./ende doctor
```
`ende doctor` checks:
- keyring file presence and permissions
- default signer configuration
- private key file paths and `0600` permissions
- recipient/trusted-sender registration consistency

To remove a registered alias later:
```bash
./ende unregister alice
```

5. Encrypt + sign (default: text to stdout):
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob
```

5-0. Encrypt from file input:
```bash
./ende encrypt -t bob -f secrets.env -o secret.txt
```

5-1. Save text output to file (optional):
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --text -o secret.txt
```

5-2. Raw binary output (optional):
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --binary -o secret.ende
```

6. Verify and decrypt:
```bash
./ende verify -i secret.ende
./ende decrypt -i secret.ende -o decrypted.txt
```

Text envelope input is also supported:
```bash
./ende verify -i secret.txt
./ende decrypt -i secret.txt -o decrypted.txt
./ende decrypt -i secret.txt --text-out
```

## Health Checks

Use `ende doctor` to validate local trust and configuration before troubleshooting a failed encrypt/decrypt flow:

```bash
./ende doctor
```

The command prints `ok`, `warn`, and `fail` results and exits non-zero when a hard failure is detected.

## Shortcuts
- `ende enc` = `ende encrypt`
- `ende dec` = `ende decrypt`
- `ende v` = `ende verify`
- `ende k` = `ende key`
- `ende rcpt` = `ende recipient`
- `ende snd` = `ende sender`
- `ende key kg` = `ende key keygen`
- `ende key ls` = `ende key list`

## Keyring location
- `~/.config/ende/keyring.yaml`
- `~/.config/ende/keys/*.agekey`
- `~/.config/ende/keys/*.signkey`

Override location (for virtual env/project-local use):
```bash
ENDE_HOME=.ende ./dist/ende key keygen --name alice
# or
ENDE_CONFIG_DIR=.ende ./dist/ende key keygen --name alice
```

## GitHub recipient mode
GitHub mode is optional and pin-based:
```bash
./ende recipient add --github octocat --key <age-recipient> --key-index 0
```
This performs GitHub SSH key lookup for identity pinning (TOFU) and stores a pin in local keyring. Encryption still uses the provided `age` recipient key.

## Auto-generated CLI options
See the generated options table and raw `--help` output:
- [CLI_HELP.md](CLI_HELP.md)

## Open Source
- License: [LICENSE](LICENSE)
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
