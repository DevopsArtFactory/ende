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

## Terminology
- `peer`: the person or device you are sending a secret to
- `share code`: the `ENDE-PUB-1:...` string used for peer onboarding
- `encrypt` / `decrypt`: the primary commands for sending and receiving secrets
- `recipient` / `sender`: lower-level trust model terms still used in advanced commands

## Install/build
```bash
go build ./cmd/ende
```

## Install with Homebrew (tap)
```bash
brew tap DevopsArtFactory/ende https://github.com/DevopsArtFactory/homebrew-ende
brew install ende
```

The Homebrew tap formula is updated automatically from Git tags through GoReleaser.

Upgrade:
```bash
brew update
brew upgrade ende
```

Verify:
```bash
ende --version
```

## Release Automation
- Tagged releases use GoReleaser to build macOS, Linux, and Windows binaries.
- GoReleaser publishes release archives and raw binaries to GitHub Releases.
- GoReleaser updates the Homebrew tap repository at [DevopsArtFactory/homebrew-ende](https://github.com/DevopsArtFactory/homebrew-ende).

Required GitHub Actions secret:
- `HOMEBREW_TAP_GITHUB_TOKEN`: token with `contents: write` access to `DevopsArtFactory/homebrew-ende`

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
1. Generate your local key and print a share code:
```bash
./ende key keygen --name alice
```

This prints:
- your recipient public key
- your signing public key
- your `share:` code (`ENDE-PUB-1:...`)

2. Re-print your share code any time:
```bash
./ende key share --name alice
```

3. Set your default signer once:
```bash
./ende key use --name alice
```

4. Register a peer from a share code:
```bash
./ende register
# share code (ENDE-PUB-1:...): ENDE-PUB-1:...
# peer name override (optional, Enter to use the shared name):
```

You can also register non-interactively:
```bash
./ende register --alias bob --share 'ENDE-PUB-1:...'
```

5. Run a local safety check before first real use:
```bash
./ende doctor
```
`ende doctor` checks:
- keyring file presence and permissions
- default signer configuration
- private key file paths and file permission safety
- peer / trusted-signing-key registration consistency

To remove a registered alias later:
```bash
./ende unregister alice
```

6. Encrypt a secret for a registered peer.

Default behavior:
- output format: armored text
- output target: stdout

Example:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob
```

Encrypt from a file:
```bash
./ende encrypt -t bob -f secrets.env -o secret.txt
```

Save armored text to a file:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob -o secret.txt
```

Write raw binary instead:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --binary -o secret.ende
```

Prompt for a secret interactively without echoing it:
```bash
./ende encrypt -t bob --prompt -o secret.txt
```
Interactive prompt notes:
- TTY input is masked so the secret is not echoed while typing.
- Empty prompt input is rejected.
- Non-interactive stdin/file workflows continue to work as before.

Review peer and output details before encrypting:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --confirm -o secret.txt
```
`--confirm` shows:
- peer alias and short fingerprint
- signer key id
- output target
- output format

For automation, you can keep the summary behavior in scripts and skip the prompt explicitly:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --confirm --yes -o secret.txt
```

7. Verify and decrypt:
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

Safer plaintext output options:
```bash
# Refuse to overwrite an existing plaintext file
./ende decrypt -i secret.ende -o decrypted.txt --no-clobber

# Write plaintext to a temporary 0600 file and print the path
./ende decrypt -i secret.ende --out-temp
```

`--out-temp` is useful when you want Ende to choose a short-lived secure file path for you.

## Peer Inspection

Show a registered recipient:
```bash
./ende recipient show bob
```

Show the trusted signing key for the same alias:
```bash
./ende sender show bob
```

List everything currently registered:
```bash
./ende key list
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
- `ende reg` = `ende register`
- `ende unreg` = `ende unregister`
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

| Skill | Description |
|-------|-------------|
| [ende-secret-share](.kiro/skills/ende-secret-share/) | ende CLI로 팀원을 peer 등록하고 시크릿을 암호화하여 클립보드로 안전하게 전달한다. |

## Open Source
- License: [LICENSE](LICENSE)
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
