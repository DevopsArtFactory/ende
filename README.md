# ende

`ende` is a Go CLI for secure developer-to-developer secret exchange using:
- recipient public-key encryption (`age` / X25519)
- sender authentication (Ed25519 signature)
- local trust root (pinned keyring)

## Security model
- A encrypts to B's recipient key -> B can decrypt.
- C cannot decrypt without matching private key.
- Signed envelopes detect tampering and sender spoofing.
- Plaintext output to stdout is blocked by default unless `--out -` is explicitly passed.

## Install/build
```bash
go build ./cmd/ende
```

## Quickstart
1. Generate local key material:
```bash
./ende key keygen --name alice
./ende key keygen --name bob
./ende key use --name alice
```

2. Export Bob recipient key and register on Alice side:
```bash
./ende key export --name bob --type recipient > bob.agepub
./ende recipient add --alias bob --key "$(cat bob.agepub)"
```

3. Encrypt + sign:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob -o secret.ende
```

4. Verify and decrypt:
```bash
./ende verify -i secret.ende
./ende decrypt -i secret.ende -o decrypted.txt
```

## Shortcuts
- `ende enc` = `ende encrypt`
- `ende dec` = `ende decrypt`
- `ende v` = `ende verify`
- `ende k` = `ende key`
- `ende rcpt` = `ende recipient`
- `ende key kg` = `ende key keygen`
- `ende key ls` = `ende key list`

## Keyring location
- `~/.config/ende/keyring.yaml`
- `~/.config/ende/keys/*.agekey`
- `~/.config/ende/keys/*.signkey`

## GitHub recipient mode
GitHub mode is optional and pin-based:
```bash
./ende recipient add --github octocat --key <age-recipient> --key-index 0
```
This performs GitHub SSH key lookup for identity pinning (TOFU) and stores a pin in local keyring. Encryption still uses the provided `age` recipient key.

## Auto-generated CLI options
See the generated options table and raw `--help` output:
- [CLI_HELP.md](/Users/kuma/Develop/opensource/ende/CLI_HELP.md)
