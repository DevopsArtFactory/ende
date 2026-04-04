# Ende Implementation Priorities and Execution Plan

## Recent Changes (since initial analysis)

### Code Refactoring
- `cmd/ende/main.go` split into 5 focused files:
  - `root.go` - CLI entrypoint, version command, debug flag
  - `key_cmd.go` - Key management (keygen, export, import, list, use, share)
  - `crypto_cmd.go` - Encrypt/decrypt/verify + helpers (resolveRecipient, loadIdentities)
  - `parties_cmd.go` - Recipient/sender/register/unregister commands
  - `prompt.go` - Interactive input helpers
  - `share.go` - Share token encode/decode

### New Features Implemented
- `ende key share` - Print share token for existing local key
- `ende unregister <alias>` - Remove recipient + sender registration
- `keyring.RemoveRecipient()` / `keyring.RemoveSender()` - Store removal methods
- `--file` / `-f` flag on encrypt as alias for `--in`

### Test Coverage Added
| Package | Coverage | Tests Added |
|---------|----------|-------------|
| internal/sign | 93.8% | sign_test.go (keygen, sign/verify, invalid inputs, determinism) |
| internal/io | 92.3% | io_test.go (file read/write, stdout, roundtrip, edge cases) |
| internal/diag | 80.0% | diag_test.go (enable/disable, env parsing) |
| internal/resolver/github | 62.5% | github_test.go (invalid input, SSH parsing, network tests) |
| internal/keyring | 38.7% | Extended: remove, empty alias, sorted output, nil map |
| cmd/ende | 3.1% | share_test.go, crypto_cmd_test.go (token encode/decode, helpers) |

---

## Quick Wins (1-2 weeks)

### 1. Mask Interactive Secret Input
**Current**: `encrypt --prompt` reads terminal input as plain text.
**Improvement**: Switch to TTY-aware masked input while keeping stdin/file flows unchanged.

```go
// cmd/ende/prompt.go
func readPromptSecret(in io.Reader, errw io.Writer) ([]byte, error) {
    // 1. Detect whether stdin is a TTY
    // 2. If TTY, use term.ReadPassword for masked input
    // 3. If not TTY, fall back to current buffered reader behavior
    // 4. Normalize trailing newline and reject empty input
}
```

### 2. Add `ende doctor`
**Current**: Safe setup checks are distributed across runtime failures.
**Improvement**: Add one preflight command that validates local trust and file state before the user encrypts/decrypts.

```go
// cmd/ende/doctor_cmd.go
type CheckResult struct {
    Name    string
    Status  string // ok, warn, fail
    Message string
}

func runDoctor() []CheckResult {
    // 1. Load keyring
    // 2. Validate keyring path + file mode
    // 3. Validate private key paths + permissions
    // 4. Validate default signer exists
    // 5. Validate recipient/sender pair consistency
    return nil
}
```

### 3. Add Recipient Confirmation Before Encryption
**Current**: Encryption resolves aliases immediately with no review step.
**Improvement**: Add a human-readable summary before encryption, especially for first-send and multi-recipient flows.

```go
// cmd/ende/crypto_cmd.go
type EncryptSummary struct {
    SignerID   string
    Recipients []string
    Out        string
    TextOut    bool
}

func confirmEncrypt(summary EncryptSummary) error {
    // Print alias + short fingerprint + output mode
    // Require explicit confirmation unless --yes
    return nil
}
```

### 4. Safer Plaintext File Output
**Current**: stdout is protected, but file outputs rely on the caller to choose safe paths and overwrite behavior.
**Improvement**: Harden plaintext file writes without breaking automation.

```go
// internal/io/io.go
type WriteOptions struct {
    NoClobber bool
    Mode      os.FileMode
}

func WritePlaintextFile(path string, data []byte, opts WriteOptions) error {
    // Force 0600 for plaintext output
    // Refuse overwrite when NoClobber is true
    return nil
}
```

---

## Phase 1: Core Security Enhancement (1-2 months)

### 1.1 Operator Safety Milestone
1. Mask interactive prompt input
2. Add `ende doctor`
3. Add recipient confirmation and send summary
4. Add safer plaintext file output defaults

### 1.2 Key Backup Implementation

**File Structure**:
```
internal/backup/
  ├── backup.go          # Backup logic
  ├── restore.go         # Recovery logic
  └── shamir.go          # Shamir Secret Sharing
```

**Implementation Example**:
```go
// internal/backup/backup.go
package backup

import (
    "crypto/rand"
    "filippo.io/age"
    "golang.org/x/crypto/scrypt"
)

type BackupOptions struct {
    Password      string
    OutputPath    string
    IncludeKeys   []string // Backup specific keys only
}

func CreateBackup(store *keyring.Store, opts BackupOptions) error {
    // 1. Collect keyring + private key files
    data := collectKeyData(store, opts.IncludeKeys)
    
    // 2. Password-based encryption
    salt := make([]byte, 32)
    rand.Read(salt)
    
    key, _ := scrypt.Key([]byte(opts.Password), salt, 32768, 8, 1, 32)
    
    // 3. Encrypt with Age
    recipient, _ := age.NewScryptRecipient(opts.Password)
    encrypted := encryptWithAge(data, recipient)
    
    // 4. Save to file
    return os.WriteFile(opts.OutputPath, encrypted, 0600)
}

func RestoreBackup(backupPath, password string) error {
    // Decrypt and restore in reverse order
}
```

### 1.3 Key Rotation Implementation
**File Structure**:
```
internal/rotation/
  ├── rotation.go        # Rotation logic
  ├── tracker.go         # Rotation history tracking
  └── reencrypt.go       # Re-encryption
```

**Implementation Example**:
```go
// internal/rotation/rotation.go
package rotation

type RotationPlan struct {
    OldKeyID      string
    NewKeyID      string
    AffectedFiles []string // Files needing re-encryption
}

func RotateKey(store *keyring.Store, keyID string, opts RotationOptions) error {
    // 1. Generate new key
    newKey := generateNewKey(keyID + "-v2")
    
    // 2. Archive old key
    archiveOldKey(store, keyID)
    
    // 3. Register new key
    store.AddKey(newKey)
    
    // 4. Create rotation plan
    plan := createRotationPlan(keyID, newKey.ID)
    
    // 5. Display plan to user
    fmt.Printf("Rotation plan:\n")
    fmt.Printf("  Old key: %s\n", plan.OldKeyID)
    fmt.Printf("  New key: %s\n", plan.NewKeyID)
    fmt.Printf("  Files to re-encrypt: %d\n", len(plan.AffectedFiles))
    
    // 6. Execute after confirmation
    if opts.AutoReencrypt {
        return executeRotation(plan)
    }
    
    return nil
}
```

### 1.3 Key Revocation Implementation
**File Structure**:
```
internal/revocation/
  ├── revocation.go      # Revocation logic
  ├── list.go            # Revocation list management
  └── verify.go          # Revocation verification
```

**Keyring Extension**:
```go
// internal/keyring/keyring.go
type RevokedEntry struct {
    KeyID     string    `yaml:"key_id"`
    RevokedAt time.Time `yaml:"revoked_at"`
    Reason    string    `yaml:"reason"`
    RevokedBy string    `yaml:"revoked_by"`
}

type File struct {
    Recipients map[string]RecipientEntry `yaml:"recipients"`
    Keys       map[string]KeyEntry       `yaml:"keys"`
    Senders    map[string]SenderEntry    `yaml:"senders,omitempty"`
    Revoked    []RevokedEntry            `yaml:"revoked,omitempty"` // Added
    Defaults   Defaults                  `yaml:"defaults,omitempty"`
}
```

---

## Phase 2: Team Collaboration Features (2-3 months)

### 2.1 Team Keyring Implementation
**File Structure**:
```
internal/team/
  ├── team.go            # Team management
  ├── sync.go            # Git synchronization
  ├── member.go          # Member management
  └── rbac.go            # Role-based access control
```

**Team Configuration File**:
```yaml
# .ende/team.yaml
name: backend-team
repository: git@github.com:org/keys.git
members:
  - id: alice
    role: admin
    public_key: age1...
  - id: bob
    role: member
    public_key: age1...
roles:
  admin:
    - manage_members
    - rotate_keys
    - encrypt
    - decrypt
  member:
    - encrypt
    - decrypt
```

### 2.2 Secret Bundle Implementation
**File Structure**:
```
internal/bundle/
  ├── bundle.go          # Bundle creation/management
  ├── format.go          # Bundle format
  └── extract.go         # Bundle extraction
```

**Bundle Format**:
```json
{
  "version": "ende-bundle-v1",
  "created_at": "2024-03-05T10:00:00Z",
  "secrets": [
    {
      "name": "AWS_ACCESS_KEY",
      "envelope": "base64-encoded-envelope",
      "metadata": {
        "description": "Production AWS access key",
        "expires_at": "2024-06-05T10:00:00Z"
      }
    },
    {
      "name": "DATABASE_URL",
      "envelope": "base64-encoded-envelope"
    }
  ]
}
```

### 2.3 CI/CD Integration
**GitHub Action Creation**:
```yaml
# .github/actions/ende-decrypt/action.yml
name: 'Ende Decrypt'
description: 'Decrypt secrets using Ende'
inputs:
  input:
    description: 'Input envelope file'
    required: true
  output:
    description: 'Output file path'
    required: true
  private-key:
    description: 'Private key (from secrets)'
    required: true
runs:
  using: 'composite'
  steps:
    - name: Setup Ende
      run: |
        curl -L https://github.com/kuma/ende/releases/latest/download/ende-linux-amd64 -o /usr/local/bin/ende
        chmod +x /usr/local/bin/ende
    - name: Decrypt
      run: |
        echo "${{ inputs.private-key }}" > /tmp/key.agekey
        ENDE_CONFIG_DIR=/tmp/.ende ende decrypt -i ${{ inputs.input }} -o ${{ inputs.output }}
      env:
        ENDE_PRIVATE_KEY: ${{ inputs.private-key }}
```

---

## Phase 3: Advanced Features (3-6 months)

### 3.1 IDE Plugin (VS Code)
**Project Structure**:
```
vscode-ende/
  ├── package.json
  ├── src/
  │   ├── extension.ts      # Main extension
  │   ├── commands/
  │   │   ├── encrypt.ts
  │   │   ├── decrypt.ts
  │   │   └── keyManagement.ts
  │   ├── providers/
  │   │   ├── hoverProvider.ts    # Decryption preview
  │   │   └── codeActionProvider.ts
  │   └── utils/
  │       └── endeClient.ts       # Ende CLI wrapper
  └── resources/
      └── icons/
```

**Key Features**:
```typescript
// src/commands/encrypt.ts
export async function encryptSelection(editor: vscode.TextEditor) {
    const selection = editor.selection;
    const text = editor.document.getText(selection);
    
    // Select recipients
    const recipients = await vscode.window.showQuickPick(
        getRecipients(),
        { canPickMany: true, placeHolder: 'Select recipients' }
    );
    
    // Call Ende CLI
    const encrypted = await endeClient.encrypt(text, recipients);
    
    // Replace selection
    editor.edit(editBuilder => {
        editBuilder.replace(selection, encrypted);
    });
}
```

### 3.2 MFA Support
**File Structure**:
```
internal/mfa/
  ├── mfa.go             # MFA interface
  ├── totp.go            # TOTP implementation
  ├── webauthn.go        # WebAuthn (YubiKey)
  └── config.go          # MFA configuration
```

**Implementation**:
```go
// internal/mfa/totp.go
package mfa

import (
    "github.com/pquerna/otp/totp"
)

type TOTPConfig struct {
    Secret string
    Issuer string
    Account string
}

func SetupTOTP(account string) (*TOTPConfig, string, error) {
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "Ende",
        AccountName: account,
    })
    if err != nil {
        return nil, "", err
    }
    
    // Generate QR code URL
    qrURL := key.URL()
    
    return &TOTPConfig{
        Secret:  key.Secret(),
        Issuer:  "Ende",
        Account: account,
    }, qrURL, nil
}

func VerifyTOTP(secret, code string) bool {
    return totp.Validate(code, secret)
}
```

### 3.3 Policy Engine
**File Structure**:
```
internal/policy/
  ├── policy.go          # Existing file
  ├── engine.go          # Policy engine
  ├── rules.go           # Rule definitions
  └── evaluator.go       # Rule evaluation
```

**Policy File**:
```yaml
# .ende/policy.yaml
version: 1
policies:
  - name: production-access
    description: Production secrets access control
    rules:
      - effect: allow
        principals:
          - alice
          - bob
        actions:
          - decrypt
        resources:
          - "production/*"
        conditions:
          time:
            after: "09:00"
            before: "18:00"
          mfa_required: true
          
      - effect: deny
        principals:
          - "intern-*"
        actions:
          - decrypt
        resources:
          - "production/*"
```

---

## Testing Strategy

### Unit Tests
```bash
# Test all packages
go test ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Goal: 80%+ coverage
```

### Integration Tests
```go
// internal/integration_test.go
func TestEndToEndEncryptDecrypt(t *testing.T) {
    // 1. Setup temporary environment
    tmpDir := t.TempDir()
    os.Setenv("ENDE_CONFIG_DIR", tmpDir)
    
    // 2. Generate keys
    runCommand(t, "key", "keygen", "--name", "alice")
    runCommand(t, "key", "keygen", "--name", "bob")
    
    // 3. Register recipient
    // ...
    
    // 4. Encrypt
    encrypted := runCommand(t, "encrypt", "-t", "bob", "-i", "test.txt")
    
    // 5. Decrypt
    decrypted := runCommand(t, "decrypt", "-i", encrypted)
    
    // 6. Verify
    assert.Equal(t, original, decrypted)
}
```

### Security Tests
```bash
# Static analysis
gosec ./...

# Dependency vulnerability scan
go list -json -m all | nancy sleuth

# Fuzzing
go test -fuzz=FuzzDecodeEnvelope -fuzztime=30s
```

---

## Performance Benchmarks

### Add Benchmarks
```go
// internal/crypto/envelope_bench_test.go
func BenchmarkSeal(b *testing.B) {
    id := mustIdentity(b)
    signPub, signPriv := mustSignKeys(b)
    plaintext := make([]byte, 1024) // 1KB
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        Seal(plaintext, []age.Recipient{id.Recipient()}, 
             "alice", signPub, signPriv, nil)
    }
}

func BenchmarkOpen(b *testing.B) {
    // ...
}
```

### Performance Goals
- 1KB encryption: < 1ms
- 1KB decryption: < 1ms
- 1MB encryption: < 100ms
- Key generation: < 100ms

---

## Documentation Plan

### 1. API Documentation
```bash
# Generate GoDoc
godoc -http=:6060

# Or auto-publish to pkg.go.dev
```

### 2. User Guide
```
docs/
  ├── getting-started.md
  ├── key-management.md
  ├── team-collaboration.md
  ├── ci-cd-integration.md
  ├── security-best-practices.md
  └── troubleshooting.md
```

### 3. Developer Guide
```
docs/dev/
  ├── architecture.md
  ├── contributing.md
  ├── testing.md
  └── release-process.md
```

---

## Release Plan

### v0.2.0 (Current + Quick Wins)
- Timestamp verification
- Basic audit logging
- Shell autocompletion
- Bug fixes

### v0.3.0 (Phase 1)
- Key backup/recovery
- Key rotation
- Key revocation

### v0.4.0 (Phase 2)
- Team keyring
- Secret bundles
- CI/CD integration

### v1.0.0 (Phase 3)
- IDE plugins
- MFA support
- Policy engine
- Production ready

---

## Resource Requirements

### Development Personnel
- Phase 1: 1 full-time (2 months)
- Phase 2: 1-2 full-time (3 months)
- Phase 3: 2-3 full-time (6 months)

### Infrastructure
- GitHub Actions (CI/CD)
- Test environments
- Documentation hosting (GitHub Pages)

### Community
- Discord/Slack channel
- GitHub Discussions
- Monthly release notes

---

## Success Metrics

### Technical Metrics
- Test coverage > 80%
- Zero security vulnerabilities
- Pass performance benchmarks

### User Metrics
- GitHub Stars > 1000
- Weekly downloads > 500
- Issue response time < 48 hours

### Business Metrics
- Enterprise adoption > 10 companies
- Community contributors > 20
- Plugin ecosystem > 5 plugins
