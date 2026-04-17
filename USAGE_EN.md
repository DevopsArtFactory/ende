# Ende CLI Usage Guide (Sender/Receiver Workflow)

## 1. Overview
`ende` is a CLI for exchanging secrets (tokens/passwords/etc.) between developers using encrypted payloads instead of plaintext.

Core guarantees:
- Encrypted with recipient public key so **only intended recipients can decrypt**
- Signed by sender so **tampering/spoofing is detectable**
- Local keyring is the trust root (GitHub username mode is optional)
- Decrypt requires a **trusted sender pin** (`sender_key_id` + signing public key match)

## Install (Homebrew tap)
```bash
brew tap DevopsArtFactory/ende https://github.com/DevopsArtFactory/homebrew-ende
brew install ende
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

---

## 2. Initial Setup (One-time per user)
Each developer generates their own local key once.

```bash
./ende key keygen --name <my-id>
```

Example:
```bash
./ende key keygen --name alice
```

`keygen` prints:
- your recipient public key
- your signing public key
- your `share:` code (`ENDE-PUB-1:...`)

You can print the share code again later:

```bash
./ende key share --name alice
```

Set your default signer once:

```bash
./ende key use --name alice
```

Generated assets:
- `~/.config/ende/keyring.yaml`
- `~/.config/ende/keys/<id>.agekey` (decryption private key)
- `~/.config/ende/keys/<id>.signkey` (signing private key)

---

## 3. Sender (Alice) Workflow

### 3-1) Register Bob from a share code
Bob sends his `share:` code to Alice.

On Alice's side:
```bash
./ende register
# share code (ENDE-PUB-1:...): ENDE-PUB-1:...
# peer name override (optional, Enter to use the shared name):
```

Non-interactive form:
```bash
./ende register --alias bob --share 'ENDE-PUB-1:...'
```

### 3-2) Run a local safety check
```bash
./ende doctor
```

### 3-3) Encrypt + sign secret
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob
```

Important:
- Default output is armored text to stdout.
- `--sign-as` is required unless a default signer is set via `ende key use`.
- `--to` can be repeated for multi-recipient delivery.

Multi-recipient example:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob -t diana -o secret.ende
```

Encrypt from a file:
```bash
./ende encrypt -t bob -f secrets.env -o secret.txt
```

Write raw binary instead of text:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --binary -o secret.ende
```

Prompt for a secret interactively:
```bash
./ende encrypt -t bob --prompt -o secret.txt
```

Review peer and output details before encrypting:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --confirm -o secret.txt
```

For automation:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --confirm --yes -o secret.txt
```

---

## 4. Receiver (Bob) Workflow

### 4-1) Verify signature first
```bash
./ende verify -i secret.ende
```

### 4-2) Decrypt (verification required by default)
```bash
./ende decrypt -i secret.ende -o secret.txt
```

Text envelope (armored) input is also supported:
```bash
./ende decrypt -i secret.txt -o secret.out
```

Important:
- Default is `--verify-required=true`; decrypt fails if signature verification fails.
- If sender is not pinned in trusted senders, decrypt fails.
- Plaintext stdout is blocked by default. Use `--out -` explicitly to allow stdout.

Explicit stdout example:
```bash
./ende decrypt -i secret.ende -o -
```

Other plaintext output options:
```bash
./ende decrypt -i secret.ende -o decrypted.txt --no-clobber
./ende decrypt -i secret.ende --out-temp
./ende decrypt -i secret.txt --text-out
```

---

## 5. GitHub Username Mode (Optional)
The default trust model is the local keyring. GitHub mode is a convenience layer.

Register example:
```bash
./ende recipient add --github octocat --key "age1..." --key-index 0
```

Behavior:
- Looks up GitHub SSH keys and stores a TOFU pin
- On re-registration, pin mismatch causes hard failure
- Actual encryption still uses the provided `age` recipient key (`--key`)

---

## 6. Command Reference

### Command aliases (shortcuts)
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

## 6-1) key
### `ende key keygen`
Generate local key material.

Options:
- `--name <id>`: key ID (required)
- `--set-default <bool>`: set this key as default signer (default `true`)
- `--export-public`: export recipient/signing public keys to files
- `--export-dir <path>`: directory for exported public key files
- `--export-prefix <name>`: file prefix for exported files (default: `--name`)

### `ende key export`
Export public key material.

Options:
- `--name <id>`: key ID (required)
- `--type recipient|signing-public`: export type (required)

### `ende key import`
Import recipient public key as alias.

Options:
- `--name <alias>`: recipient alias (required)
- `--file <path>`: file containing age recipient key (required)

### `ende key list`
List local keys, recipients, and trusted senders.

### `ende key use`
Set default signer key ID for `encrypt`.

Options:
- `--name <id>`: key ID
- positional arg `<id>` is also supported (`ende key use alice`)

### `ende key share`
Print a share code for an existing local key.

Options:
- `--name <id>`: key ID
- positional arg `<id>` is also supported (`ende key share alice`)

---

## 6-2) recipient
### `ende recipient add`
Add recipient alias.

Options:
- `--alias <name>`: alias (required for local mode)
- `--key <age1...>`: age recipient public key (required)
- `--share <token>`: share token (`ENDE-PUB-1:...`) for recipient+sender auto registration
- `--github <username>`: GitHub username (optional)
- `--key-index <n>`: GitHub SSH key index to pin (default `0`)

### `ende recipient show <alias>`
Show recipient details.

### `ende recipient rotate <alias>`
Rotate recipient public key.

Options:
- `--key <age1...>`: new recipient public key (required)

---

## 6-3) encrypt / decrypt / verify
### `ende encrypt`
Encrypt + sign payload.

Options:
- `-t, --to <alias|github:user|age1...>`: recipient target(s), repeatable (required)
- `-s, --sign-as <key-id>`: sender signing key ID (optional if default signer exists)
- `-i, --in <path|->`: input (default `-` = stdin)
- `-f, --file <path>`: input file path (alias of `--in`)
- `-o, --out <path|->`: output (default `-` = stdout)
- `--text`: output ASCII-armored envelope (default `true`)
- `--binary`: output raw binary envelope
- `--prompt`: prompt secret input interactively
- `--confirm`: show a summary and ask before encrypting
- `--yes`: skip the confirmation prompt when `--confirm` is used

### `ende decrypt`
Verify + decrypt envelope.

Options:
- `-i, --in <path|->`: input (default `-`)
- `-o, --out <path|->`: plaintext output (`--out -` must be explicit)
- `--verify-required <bool>`: enforce signature verification (default `true`)
- `--text-out`: print decrypted plaintext to stdout
- `--no-clobber`: refuse to overwrite an existing plaintext file
- `--out-temp`: write plaintext to a temporary `0600` file and print the path

### `ende verify`
Verify signature without decrypting.

Options:
- `-i, --in <path|->`: input (default `-`)

---

## 6-4) sender
### `ende sender add`
Add trusted sender signing key pin.

Options:
- `--id <sender-id>`: sender ID to trust (required)
- `--signing-public <base64>`: Ed25519 public key (required)
- `--github <username>`: optional metadata
- `--force`: overwrite existing sender

### `ende sender show <id>`
Show trusted sender details.

### `ende sender rotate <id>`
Rotate trusted sender signing public key.

Options:
- `--signing-public <base64>`: new Ed25519 public key (required)

### `ende sender list`
List trusted senders.

---

## 6-5) register
### `ende register`
Register recipient + trusted sender in one step.

Options:
- `--alias <name>`: alias to register
- `--share <token>`: share token (`ENDE-PUB-1:...`) for one-step registration
- `--recipient-key <age1...>`: recipient key for manual one-step registration
- `--signing-public <base64>`: sender signing public key for manual one-step registration
- `--force`: overwrite existing recipient/sender entries

### `ende unregister <alias>`
Remove a registered alias and its matching trusted sender entry.

---

## 7. Security Design Considerations

- Trust root
  - Local keyring with pinned keys is the default trust root
  - GitHub username is convenience metadata, not a trust root
  - Trusted sender pin (`sender id -> signing public key`) is mandatory for secure decrypt

- No custom crypto primitive implementation
  - Uses `filippo.io/age`
  - Avoids implementing custom cryptographic algorithms

- Authentication + integrity
  - Ed25519 signature is required
  - Signature target is `ciphertext + canonical metadata (CBOR)`
  - Verification is done before decryption for early rejection

- Secure defaults
  - `--sign-as` required in `encrypt` unless default signer is configured
  - `verify-required=true` by default in `decrypt`
  - unknown sender IDs are rejected during decrypt
  - Plaintext stdout blocked by default (`--out -` required)
  - Private key file permission `0600` enforced on Unix-like systems
  - Windows skips POSIX mode checks because NTFS ACLs do not map to `0600`

- Operational safety
  - Secrets are handled via file/stdin paths, not CLI secret arguments
  - Reduces shell history leakage risk

---

## 8. Recommended Team Operations
1. Standardize key ID naming conventions.
2. Verify recipient fingerprints out-of-band during onboarding.
3. Rotate keys periodically (`recipient rotate`).
4. Add verify/decrypt regression checks in CI.

---

## 9. Auto-generated `--help` options
For the latest options table and raw help output, see:
- [CLI_HELP.md](/Users/kuma/Develop/opensource/ende/CLI_HELP.md)
