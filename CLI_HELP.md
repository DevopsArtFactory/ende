# CLI Help Snapshot

Auto-generated from command --help outputs on 2026-03-05.

## Options Table

### ende

| Flag | Description |
|---|---|
| `-h, --help` | help for ende |

### ende key

| Flag | Description |
|---|---|
| `-h, --help` | help for key |

### ende key keygen

| Flag | Description |
|---|---|
| `-h, --help` | help for keygen |
| `--name string` | key id |

### ende key export

| Flag | Description |
|---|---|
| `-h, --help` | help for export |
| `--name string` | key id |
| `--type string` | recipient\|signing-public |

### ende key import

| Flag | Description |
|---|---|
| `--file string` | file with age recipient |
| `-h, --help` | help for import |
| `--name string` | recipient alias |

### ende key list

| Flag | Description |
|---|---|
| `-h, --help` | help for list |

### ende key use

| Flag | Description |
|---|---|
| `-h, --help` | help for use |
| `--name string` | key id |

### ende recipient

| Flag | Description |
|---|---|
| `-h, --help` | help for recipient |

### ende recipient add

| Flag | Description |
|---|---|
| `--alias string` | recipient alias |
| `--github string` | github username (optional resolver) |
| `-h, --help` | help for add |
| `--key string` | age recipient public key |
| `--key-index int` | github ssh key index for pinning |

### ende recipient show

| Flag | Description |
|---|---|
| `-h, --help` | help for show |

### ende recipient rotate

| Flag | Description |
|---|---|
| `-h, --help` | help for rotate |
| `--key string` | new age recipient public key |

### ende encrypt

| Flag | Description |
|---|---|
| `-h, --help` | help for encrypt |
| `-i, --in string` | input path or - (default "-") |
| `-o, --out string` | output path or - (default "-") |
| `-s, --sign-as string` | local signing key id (optional if default signer is set) |
| `-t, --to strings` | recipient alias, github:user, or age1... public key |

### ende decrypt

| Flag | Description |
|---|---|
| `-h, --help` | help for decrypt |
| `-i, --in string` | input path or - (default "-") |
| `-o, --out string` | output plaintext path or - (explicit) |
| `--verify-required` | require signature verification (default true) |

### ende verify

| Flag | Description |
|---|---|
| `-h, --help` | help for verify |
| `-i, --in string` | input path or - (default "-") |

## Raw Help Output

### ende --help

```text
Ende securely encrypts secrets between developers

Usage:
  ende [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  decrypt     Verify and decrypt envelope
  encrypt     Encrypt and sign secret payload
  help        Help about any command
  key         Manage local keys
  recipient   Manage recipient aliases
  verify      Verify signature without decrypting

Flags:
  -h, --help   help for ende

Use "ende [command] --help" for more information about a command.
```

### ende key --help

```text
Manage local keys

Usage:
  ende key [command]

Aliases:
  key, k

Available Commands:
  export      Export public key material
  import      Import age recipient public key into recipient aliases
  keygen      Generate X25519 recipient and Ed25519 signing key pair
  list        List local keys and recipients
  use         Set default signer key ID for encrypt

Flags:
  -h, --help   help for key

Use "ende key [command] --help" for more information about a command.
```

### ende key keygen --help

```text
Generate X25519 recipient and Ed25519 signing key pair

Usage:
  ende key keygen [flags]

Aliases:
  keygen, kg

Flags:
  -h, --help          help for keygen
      --name string   key id
```

### ende key export --help

```text
Export public key material

Usage:
  ende key export [flags]

Flags:
  -h, --help          help for export
      --name string   key id
      --type string   recipient|signing-public
```

### ende key import --help

```text
Import age recipient public key into recipient aliases

Usage:
  ende key import [flags]

Flags:
      --file string   file with age recipient
  -h, --help          help for import
      --name string   recipient alias
```

### ende key list --help

```text
List local keys and recipients

Usage:
  ende key list [flags]

Aliases:
  list, ls

Flags:
  -h, --help   help for list
```

### ende key use --help

```text
Set default signer key ID for encrypt

Usage:
  ende key use [flags]

Flags:
  -h, --help          help for use
      --name string   key id
```

### ende recipient --help

```text
Manage recipient aliases

Usage:
  ende recipient [command]

Aliases:
  recipient, rcpt

Available Commands:
  add         Add recipient by alias or GitHub username
  rotate      Rotate recipient public key
  show        Show recipient details

Flags:
  -h, --help   help for recipient

Use "ende recipient [command] --help" for more information about a command.
```

### ende recipient add --help

```text
Add recipient by alias or GitHub username

Usage:
  ende recipient add [flags]

Flags:
      --alias string    recipient alias
      --github string   github username (optional resolver)
  -h, --help            help for add
      --key string      age recipient public key
      --key-index int   github ssh key index for pinning
```

### ende recipient show --help

```text
Show recipient details

Usage:
  ende recipient show <alias> [flags]

Flags:
  -h, --help   help for show
```

### ende recipient rotate --help

```text
Rotate recipient public key

Usage:
  ende recipient rotate <alias> [flags]

Flags:
  -h, --help         help for rotate
      --key string   new age recipient public key
```

### ende encrypt --help

```text
Encrypt and sign secret payload

Usage:
  ende encrypt [flags]

Aliases:
  encrypt, enc

Flags:
  -h, --help             help for encrypt
  -i, --in string        input path or - (default "-")
  -o, --out string       output path or - (default "-")
  -s, --sign-as string   local signing key id (optional if default signer is set)
  -t, --to strings       recipient alias, github:user, or age1... public key
```

### ende decrypt --help

```text
Verify and decrypt envelope

Usage:
  ende decrypt [flags]

Aliases:
  decrypt, dec

Flags:
  -h, --help              help for decrypt
  -i, --in string         input path or - (default "-")
  -o, --out string        output plaintext path or - (explicit)
      --verify-required   require signature verification (default true)
```

### ende verify --help

```text
Verify signature without decrypting

Usage:
  ende verify [flags]

Aliases:
  verify, v

Flags:
  -h, --help        help for verify
  -i, --in string   input path or - (default "-")
```
