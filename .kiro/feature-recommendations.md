# Ende Feature Development Roadmap

## Recent Progress
- Key rotation commands (`recipient rotate`, `sender rotate`) are now implemented
- `unregister` command added for removing recipient + sender entries
- `key share` command added for printing share tokens of existing keys
- CLI refactored from monolithic main.go into focused command files
- Test coverage significantly improved across all internal packages

## Current Reassessment
- The next milestone should prioritize reducing operator mistakes, not just adding platform breadth.
- The highest-leverage improvements are the ones that increase confidence at the moment of encrypt/decrypt.
- Near-term roadmap should focus on: masked secret entry, preflight diagnostics, recipient confirmation, and safer plaintext output handling.
- A second UX layer should expose the common workflow through task-oriented commands such as `setup`, `add-peer`, `send`, and `receive`.

## 1. Core Security Features

### 1.1 Key Rotation - MEDIUM PRIORITY (downgraded from HIGH)
**Current Status**: `recipient rotate` and `sender rotate` are implemented. They update the public key and fingerprint in the local keyring. Missing: re-encryption tooling, revocation list, rotation history.

**Implementation Proposal**:
```go
// Automated key rotation workflow
ende key rotate alice --auto-reencrypt

// Steps:
1. Generate new keypair
2. Search for envelopes encrypted with old key
3. Perform re-encryption
4. Archive old key (don't delete immediately)
5. Redistribute public key (generate share token)
```

**Additional Features**:
- Track rotation history
- Automatic rotation scheduling (e.g., every 90 days)
- Rotation notifications (warn 30 days before expiration)

---

### 1.2 Key Backup and Recovery - HIGH PRIORITY
**Need**: Keys are unrecoverable if lost

**Implementation Proposal**:
```bash
# Password-based backup
ende key backup --output backup.enc --password

# Shamir Secret Sharing (more secure)
ende key backup --threshold 2 --shares 3 --output-dir ./shares
# → Generates share-1.enc, share-2.enc, share-3.enc
# → Can recover with any 2 out of 3 shares

# Recovery
ende key restore --input backup.enc --password
ende key restore --shares share-1.enc,share-2.enc
```

**Additional Options**:
- Cloud backup (upload to S3/GCS in encrypted state)
- Automated periodic backups
- Backup integrity verification

---

### 1.3 Key Revocation and Revocation List - MEDIUM PRIORITY
**Problem**: No mechanism to invalidate compromised keys

**Implementation Proposal**:
```bash
# Revoke key
ende key revoke alice --reason "compromised"

# Share revocation list
ende key revoke-list --export revoked-keys.json

# Other users import revocation list
ende key revoke-list --import revoked-keys.json

# Automatic verification during decryption
ende decrypt -i secret.ende
# → Error: sender key 'alice' has been revoked
```

**Distributed Revocation List**:
- Git repository-based sharing
- Signed revocation list
- Automatic update mechanism

---

## 2. Usability Improvements

### 2.1 Safety Doctor / Preflight Checks - HIGH PRIORITY
**Why now**: Users need a quick way to confirm their local environment is safe before exchanging secrets.

**Implementation Proposal**:
```bash
ende doctor
# → Validate:
# 1. keyring path and permissions
# 2. private key file permissions
# 3. default signer configuration
# 4. recipient/sender registration consistency
# 5. stale or risky trust entries
```

**Suggested Checks**:
- Missing default signer
- Missing trusted sender for a registered recipient
- Broken private key paths
- Keyring file mode warnings
- GitHub pin mismatch or unverified GitHub-mode onboarding reminders

---

### 2.2 Safe Secret Prompt UX - HIGH PRIORITY
**Current**: `encrypt --prompt` is convenient, but it should behave like a secret input flow instead of a plain terminal read.

**Implementation Proposal**:
```bash
ende encrypt -t bob --prompt -o secret.txt
# → masked input
# → optional confirm input
# → empty input rejected
# → weak-value warning before encryption
```

**Design Goals**:
- Never echo secret input back to terminal
- Reduce accidental whitespace/newline mistakes
- Warn on obviously weak secrets without blocking all usage
- Keep non-interactive stdin/file workflows unchanged

---

### 2.3 Recipient Confirmation and Send Summary - HIGH PRIORITY
**Why now**: The most likely user mistake is encrypting to the wrong alias or overlooking who will be able to decrypt.

**Implementation Proposal**:
```bash
ende encrypt -t bob -t diana --confirm
# → recipient summary:
#    - bob (fp=abcd1234)
#    - diana (fp=efgh5678)
#    signer: alice
#    output: secret.txt
#    format: armored text
# Continue? [y/N]
```

**Suggested Behavior**:
- Default to confirmation on first-send or multi-recipient flows
- Show short fingerprints and source metadata
- Allow `--yes` for automation
- Reuse the same summary in tutorial/onboarding flows

---

### 2.4 Interactive Setup Wizard - MEDIUM PRIORITY
**Current**: Many command options create high barrier for beginners

**Implementation Proposal**:
```bash
ende init
# → Start interactive setup
# 1. Key generation (name, email)
# 2. Default settings (encryption options)
# 3. Team member registration (enter share token)
# 4. Test encryption/decryption
```

**Incremental Step**:
```bash
ende setup
ende add-peer
ende send -t bob
ende receive -i secret.ende -o secret.txt
```
This keeps the existing trust model while giving new users goal-oriented entrypoints.

---

### 2.5 GUI Tool - LOW PRIORITY
**Need**: Support users unfamiliar with CLI

**Implementation Options**:
1. **Web-based UI** (local server)
   ```bash
   ende ui --port 8080
   # → Provides GUI at http://localhost:8080
   ```

2. **Electron App**
   - Drag and drop encryption
   - Key management visualization
   - Team member management

3. **Browser Extension**
   - Direct encryption from web forms
   - GitHub/GitLab integration

---

### 2.6 IDE Plugins - MEDIUM PRIORITY
**Goal**: Integrate into development workflow

**VS Code Extension**:
```javascript
// Encrypt directly from .env file
DATABASE_URL=postgres://... // Right-click → "Encrypt with Ende"
// → DATABASE_URL=ENDE-ENC-1:...

// Decryption preview
// Show decrypted value on hover (after permission check)
```

**JetBrains Plugin**:
- Automatic detection of secrets in code
- Encryption suggestions
- Key management UI

---

### 2.7 Safer Plaintext Output Modes - MEDIUM PRIORITY
**Why now**: stdout protection already exists, but file-based plaintext output can still be made safer for day-to-day use.

**Implementation Proposal**:
```bash
ende decrypt -i secret.ende --out-temp
# → writes plaintext to a temporary 0600 file
# → prints path for short-term use

ende decrypt -i secret.ende -o secrets.txt --no-clobber
# → refuses overwrite unless explicitly allowed
```

**Additional Options**:
- Force plaintext output files to `0600`
- `--no-clobber` for safe default writes
- ephemeral display mode for one-time viewing

---

### 2.8 Shell Autocompletion - LOW PRIORITY
```bash
# Bash/Zsh/Fish autocompletion
ende completion bash > /etc/bash_completion.d/ende
ende completion zsh > ~/.zsh/completions/_ende

# Usage example:
ende enc<TAB>  # → encrypt
ende -t <TAB>  # → Show list of registered recipients
```

---

## 3. Team Collaboration Features

### 3.1 Team Keyring Sharing - HIGH PRIORITY
**Current**: Only personal keyring supported

**Implementation Proposal**:
```bash
# Initialize team keyring
ende team init --name backend-team --repo git@github.com:org/keys.git

# Add team members
ende team add-member bob --role member
ende team add-member alice --role admin

# Sync team keyring
ende team sync
# → Pull latest keyring from Git repository
# → Push local changes

# Role-based access control
- admin: Add/remove members, rotate keys
- member: Encrypt/decrypt only
- viewer: View public keys only
```

**Security Considerations**:
- Git repository stores encrypted keyring
- Encrypted with each team member's public key
- Integrity guaranteed by signatures

---

### 3.2 Secret Sharing Workflow - MEDIUM PRIORITY
**Scenario**: Transfer multiple secrets at once during onboarding

**Implementation Proposal**:
```bash
# Create secret bundle
ende bundle create onboarding.bundle
# → Interactively input multiple secrets
# AWS_ACCESS_KEY: ***
# DATABASE_URL: ***
# API_TOKEN: ***

# Encrypt bundle
ende bundle encrypt onboarding.bundle -t new-member -o onboarding.ende

# Recipient decrypts bundle
ende bundle decrypt onboarding.ende -o secrets/
# → secrets/AWS_ACCESS_KEY
# → secrets/DATABASE_URL
# → secrets/API_TOKEN
```

---

### 3.3 Secret Version Control - MEDIUM PRIORITY
**Need**: Track secret change history

**Implementation Proposal**:
```bash
# Git-based secret repository
ende vault init --repo git@github.com:org/secrets.git

# Store secret (auto-encrypted)
ende vault set production/database-url "postgres://..."
# → Git commit + push

# View history
ende vault history production/database-url
# v3 (2024-03-05): Updated by alice
# v2 (2024-02-01): Rotated by bob
# v1 (2024-01-01): Initial by alice

# Restore specific version
ende vault get production/database-url --version v2
```

---

## 4. Integration and Automation

### 4.1 CI/CD Integration - HIGH PRIORITY
**Goal**: Safely use secrets in build pipelines

**GitHub Actions**:
```yaml
# .github/workflows/deploy.yml
- name: Decrypt secrets
  uses: ende-cli/decrypt-action@v1
  with:
    input: secrets.ende
    output: .env
    key: ${{ secrets.ENDE_PRIVATE_KEY }}

- name: Deploy
  run: ./deploy.sh
  env:
    DATABASE_URL: ${{ env.DATABASE_URL }}
```

**GitLab CI**:
```yaml
decrypt_secrets:
  script:
    - ende decrypt -i secrets.ende -o .env
    - source .env
```

**Jenkins**:
```groovy
pipeline {
  stages {
    stage('Decrypt') {
      steps {
        sh 'ende decrypt -i secrets.ende -o .env'
      }
    }
  }
}
```

---

### 4.2 Kubernetes Secrets Integration - MEDIUM PRIORITY
```bash
# Create Kubernetes Secret
ende k8s create-secret my-app-secrets \
  --from-file secrets.ende \
  --namespace production

# Or decrypt directly to create
ende decrypt -i secrets.ende --text-out | \
  kubectl create secret generic my-app-secrets \
    --from-literal=DATABASE_URL=$(cat -)
```

**Operator Development**:
```yaml
# CRD definition
apiVersion: ende.io/v1
kind: EndeSecret
metadata:
  name: my-app-secrets
spec:
  envelopeRef: secrets.ende
  recipients:
    - alice
    - bob
```

---

### 4.3 HashiCorp Vault Integration - MEDIUM PRIORITY
```bash
# Store encrypted secret in Vault
ende encrypt -t ops-team | \
  vault kv put secret/production/db password=-

# Retrieve from Vault and decrypt
vault kv get -field=password secret/production/db | \
  ende decrypt -i - --text-out
```

---

### 4.4 AWS Secrets Manager Integration - LOW PRIORITY
```bash
# Store in AWS Secrets Manager
ende encrypt -t prod-team --text | \
  aws secretsmanager create-secret \
    --name prod/database \
    --secret-string file:///dev/stdin

# Retrieve and decrypt
aws secretsmanager get-secret-value \
  --secret-id prod/database \
  --query SecretString \
  --output text | \
  ende decrypt -i - --text-out
```

---

## 5. Advanced Security Features

### 5.1 Hardware Security Module (HSM) Support - LOW PRIORITY
```bash
# YubiKey integration
ende key import --yubikey --slot 1

# Use YubiKey for encryption
ende encrypt -t bob --sign-with yubikey:1

# TPM integration (Windows/Linux)
ende key import --tpm --pcr 7
```

---

### 5.2 Multi-Factor Authentication (MFA) - MEDIUM PRIORITY
```bash
# Require TOTP during decryption
ende decrypt -i secret.ende --require-mfa
# → Enter TOTP code: ******

# Configuration
ende config set mfa.enabled true
ende config set mfa.provider totp
ende mfa setup
# → Display QR code
```

---

### 5.3 Audit Logging and Monitoring - MEDIUM PRIORITY
```bash
# View audit logs
ende audit log --since 7d
# 2024-03-05 10:30:15 | alice | encrypt | to=bob | success
# 2024-03-05 10:31:22 | bob   | decrypt | from=alice | success
# 2024-03-05 10:32:10 | eve   | decrypt | from=alice | FAILED

# Export logs
ende audit export --format json --output audit.json

# SIEM integration
ende audit stream --syslog siem.company.com:514
```

---

### 5.4 Policy-Based Access Control - LOW PRIORITY
```yaml
# .ende/policy.yaml
policies:
  - name: production-secrets
    rules:
      - allow:
          senders: [alice, bob]
          recipients: [prod-team]
          time: business-hours
      - deny:
          senders: [intern-*]
          
  - name: pci-compliance
    rules:
      - require:
          mfa: true
          key-rotation: 90d
          audit-log: enabled
```

---

## 6. Developer Experience Improvements

### 6.1 Template System - LOW PRIORITY
```bash
# Define template
# templates/aws-credentials.tmpl
AWS_ACCESS_KEY_ID={{ .AccessKey }}
AWS_SECRET_ACCESS_KEY={{ .SecretKey }}
AWS_REGION={{ .Region }}

# Use template
ende template render aws-credentials.tmpl \
  --var AccessKey=AKIA... \
  --var SecretKey=... \
  --var Region=us-east-1 | \
  ende encrypt -t devops-team -o aws-creds.ende
```

---

### 6.2 Secret Validation - MEDIUM PRIORITY
```bash
# Validate secret format
ende validate -i secrets.ende --schema schema.json

# schema.json
{
  "DATABASE_URL": {
    "type": "postgres-url",
    "required": true
  },
  "API_KEY": {
    "type": "string",
    "pattern": "^sk-[a-zA-Z0-9]{32}$"
  }
}
```

---

### 6.3 Secret Generator - LOW PRIORITY
```bash
# Generate secure secrets
ende generate password --length 32 --special-chars
ende generate api-key --format uuid
ende generate ssh-key --type ed25519

# Generate and encrypt immediately
ende generate password | ende encrypt -t alice -o password.ende
```

---

## 7. Performance and Scalability

### 7.1 Large File Support - MEDIUM PRIORITY
**Current**: Loads entire file into memory

**Improvement**:
```go
// Streaming encryption
ende encrypt -t bob -i large-file.zip -o large-file.ende --stream

// Chunk-based processing
// Limit memory usage
```

---

### 7.2 Parallel Processing - LOW PRIORITY
```bash
# Encrypt multiple files simultaneously
ende encrypt -t team --batch *.env

# Parallel processing for multiple recipients
ende encrypt -t alice,bob,charlie,diana --parallel
```

---

### 7.3 Caching - LOW PRIORITY
```bash
# Public key caching
ende config set cache.enabled true
ende config set cache.ttl 1h

# GitHub API response caching
# Reduce network requests
```

---

## 8. Documentation and Education

### 8.1 Interactive Tutorial - MEDIUM PRIORITY
```bash
ende tutorial start
# → Step-by-step guide
# 1. Key generation
# 2. Team member registration
# 3. First encryption
# 4. Decryption
# 5. Key rotation
```

---

### 8.2 Security Best Practices Guide - HIGH PRIORITY
- Key management policies
- Team onboarding procedures
- Incident response playbook
- Compliance checklists
- Recipient fingerprint verification checklist
- Recommended `ende doctor` checks before first production use
- Plaintext handling guidance for local development machines

---

### 8.3 Migration Tools - MEDIUM PRIORITY
```bash
# Migrate from other tools
ende migrate from-sops --input secrets.yaml
ende migrate from-age --input secrets.age
ende migrate from-gpg --input secrets.gpg

# Export to other tools
ende migrate to-sops --input secrets.ende
```

---

## 9. Implementation Priority by Phase

### Phase 1: Core Security (1-2 months)
1. Safe secret prompt UX
2. `ende doctor` preflight command
3. Recipient confirmation / first-send summary
4. Safer plaintext file output modes

### Phase 2: Team Collaboration (2-3 months)
1. Key backup/recovery
2. Team keyring sharing
3. CI/CD integration
4. Interactive setup wizard

### Phase 3: Advanced Features (3-6 months)
1. Secret bundles
2. IDE plugins
3. Kubernetes integration
4. MFA support

### Phase 4: Expansion and Optimization (6+ months)
1. Policy-based access control
2. GUI tools
3. HSM support
4. Advanced monitoring

---

## 10. Community Contribution Ideas

### 10.1 Plugin Ecosystem
- Custom key storage plugins
- Encryption backend plugins
- Audit log transmission plugins

### 10.2 Language Bindings
- Python SDK
- Node.js SDK
- Rust SDK
- Go library (currently CLI only)

### 10.3 Cloud Services
- Ende-as-a-Service (optional)
- Key escrow service
- Team keyring hosting

---

## Conclusion

Ende is built on a solid foundation, and the next step should optimize for
safe everyday usage before expanding into broader platform features.

Priorities:
1. **Operator Safety** (masked prompts, recipient confirmation, safer plaintext handling)
2. **Security Assurance** (`ende doctor`, trust checks, backup/recovery)
3. **Team Collaboration** (shared keyring, CI/CD)
4. **Expansion** (GUI, IDE plugins, integrations)
