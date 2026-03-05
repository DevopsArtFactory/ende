# CLI Help Snapshot

Auto-generated from command --help outputs on 2026-03-05.

## Options Table

### ende

| Flag | Description |
|---|---|
| `--debug` | enable diagnostic logs to stderr |
| `-h, --help` | help for ende |

### ende key

| Flag | Description |
|---|---|
| `-h, --help` | help for key |
| `--debug` | enable diagnostic logs to stderr |

### ende key keygen

| Flag | Description |
|---|---|
| `--export-dir string` | directory for exported public key files (default ".") |
| `--export-prefix string` | filename prefix for exported files (defaults to --name) |
| `--export-public` | export public keys to files |
| `-h, --help` | help for keygen |
| `--name string` | key id |
| `--set-default` | set generated key as default signer (default true) |
| `--debug` | enable diagnostic logs to stderr |

### ende key export

| Flag | Description |
|---|---|
| `-h, --help` | help for export |
| `--name string` | key id |
| `--type string` | recipient\|signing-public |
| `--debug` | enable diagnostic logs to stderr |

### ende key import

| Flag | Description |
|---|---|
| `--file string` | file with age recipient |
| `-h, --help` | help for import |
| `--name string` | recipient alias |
| `--debug` | enable diagnostic logs to stderr |

### ende key list

| Flag | Description |
|---|---|
| `-h, --help` | help for list |
| `--debug` | enable diagnostic logs to stderr |

### ende key use

| Flag | Description |
|---|---|
| `-h, --help` | help for use |
| `--name string` | key id |
| `--debug` | enable diagnostic logs to stderr |

### ende recipient

| Flag | Description |
|---|---|
| `-h, --help` | help for recipient |
| `--debug` | enable diagnostic logs to stderr |

### ende recipient add

| Flag | Description |
|---|---|
| `--alias string` | recipient alias |
| `--force` | overwrite existing recipient alias |
| `--github string` | github username (optional resolver) |
| `-h, --help` | help for add |
| `--key string` | age recipient public key |
| `--key-index int` | github ssh key index for pinning |
| `--share string` | share token from keygen output |
| `--debug` | enable diagnostic logs to stderr |

### ende recipient show

| Flag | Description |
|---|---|
| `-h, --help` | help for show |
| `--debug` | enable diagnostic logs to stderr |

### ende recipient rotate

| Flag | Description |
|---|---|
| `-h, --help` | help for rotate |
| `--key string` | new age recipient public key |
| `--debug` | enable diagnostic logs to stderr |

### ende sender

| Flag | Description |
|---|---|
| `-h, --help` | help for sender |
| `--debug` | enable diagnostic logs to stderr |

### ende sender add

| Flag | Description |
|---|---|
| `--force` | overwrite existing sender entry |
| `--github string` | optional github username metadata |
| `-h, --help` | help for add |
| `--id string` | sender id to trust |
| `--signing-public string` | sender Ed25519 public key (base64) |
| `--debug` | enable diagnostic logs to stderr |

### ende sender show

| Flag | Description |
|---|---|
| `-h, --help` | help for show |
| `--debug` | enable diagnostic logs to stderr |

### ende sender rotate

| Flag | Description |
|---|---|
| `-h, --help` | help for rotate |
| `--signing-public string` | new sender Ed25519 public key (base64) |
| `--debug` | enable diagnostic logs to stderr |

### ende sender list

| Flag | Description |
|---|---|
| `-h, --help` | help for list |
| `--debug` | enable diagnostic logs to stderr |

### ende register

| Flag | Description |
|---|---|
| `--alias string` | alias to register |
| `--force` | overwrite existing recipient/sender entries |
| `-h, --help` | help for register |
| `--recipient-key string` | age recipient public key |
| `--share string` | share token from keygen output |
| `--signing-public string` | Ed25519 signing public key (base64) |
| `--debug` | enable diagnostic logs to stderr |

### ende encrypt

| Flag | Description |
|---|---|
| `--binary` | output raw binary envelope |
| `-h, --help` | help for encrypt |
| `-i, --in string` | input path or - (default "-") |
| `-o, --out string` | output path or - (default "-") |
| `--prompt` | prompt for secret value interactively |
| `-s, --sign-as string` | local signing key id (optional if default signer is set) |
| `--text` | output ASCII-armored envelope for copy/paste transport (default true) (default true) |
| `-t, --to strings` | recipient alias, github:user, or age1... public key |
| `--debug` | enable diagnostic logs to stderr |

### ende decrypt

| Flag | Description |
|---|---|
| `-h, --help` | help for decrypt |
| `-i, --in string` | input path or - (default "-") |
| `-o, --out string` | output plaintext path or - (explicit) |
| `--text-out` | print decrypted plaintext to stdout |
| `--verify-required` | require signature verification (default true) |
| `--debug` | enable diagnostic logs to stderr |

### ende verify

| Flag | Description |
|---|---|
| `-h, --help` | help for verify |
| `-i, --in string` | input path or - (default "-") |
| `--debug` | enable diagnostic logs to stderr |

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
  register    Register recipient and trusted sender in one step
  sender      Manage trusted sender signing keys
  verify      Verify signature without decrypting

Flags:
      --debug   enable diagnostic logs to stderr
  -h, --help    help for ende

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

Global Flags:
      --debug   enable diagnostic logs to stderr

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
      --export-dir string      directory for exported public key files (default ".")
      --export-prefix string   filename prefix for exported files (defaults to --name)
      --export-public          export public keys to files
  -h, --help                   help for keygen
      --name string            key id
      --set-default            set generated key as default signer (default true)

Global Flags:
      --debug   enable diagnostic logs to stderr
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

Global Flags:
      --debug   enable diagnostic logs to stderr
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

Global Flags:
      --debug   enable diagnostic logs to stderr
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

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende key use --help

```text
Set default signer key ID for encrypt

Usage:
  ende key use [flags]

Flags:
  -h, --help          help for use
      --name string   key id

Global Flags:
      --debug   enable diagnostic logs to stderr
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

Global Flags:
      --debug   enable diagnostic logs to stderr

Use "ende recipient [command] --help" for more information about a command.
```

### ende recipient add --help

```text
Add recipient by alias or GitHub username

Usage:
  ende recipient add [flags]

Flags:
      --alias string    recipient alias
      --force           overwrite existing recipient alias
      --github string   github username (optional resolver)
  -h, --help            help for add
      --key string      age recipient public key
      --key-index int   github ssh key index for pinning
      --share string    share token from keygen output

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende recipient show --help

```text
Show recipient details

Usage:
  ende recipient show <alias> [flags]

Flags:
  -h, --help   help for show

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende recipient rotate --help

```text
Rotate recipient public key

Usage:
  ende recipient rotate <alias> [flags]

Flags:
  -h, --help         help for rotate
      --key string   new age recipient public key

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende sender --help

```text
Manage trusted sender signing keys

Usage:
  ende sender [command]

Aliases:
  sender, snd

Available Commands:
  add         Add trusted sender signing public key
  list        List trusted senders
  rotate      Rotate trusted sender signing public key
  show        Show trusted sender details

Flags:
  -h, --help   help for sender

Global Flags:
      --debug   enable diagnostic logs to stderr

Use "ende sender [command] --help" for more information about a command.
```

### ende sender add --help

```text
Add trusted sender signing public key

Usage:
  ende sender add [flags]

Flags:
      --force                   overwrite existing sender entry
      --github string           optional github username metadata
  -h, --help                    help for add
      --id string               sender id to trust
      --signing-public string   sender Ed25519 public key (base64)

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende sender show --help

```text
Show trusted sender details

Usage:
  ende sender show <id> [flags]

Flags:
  -h, --help   help for show

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende sender rotate --help

```text
Rotate trusted sender signing public key

Usage:
  ende sender rotate <id> [flags]

Flags:
  -h, --help                    help for rotate
      --signing-public string   new sender Ed25519 public key (base64)

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende sender list --help

```text
List trusted senders

Usage:
  ende sender list [flags]

Aliases:
  list, ls

Flags:
  -h, --help   help for list

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende register --help

```text
Register recipient and trusted sender in one step

Usage:
  ende register [flags]

Aliases:
  register, reg

Flags:
      --alias string            alias to register
      --force                   overwrite existing recipient/sender entries
  -h, --help                    help for register
      --recipient-key string    age recipient public key
      --share string            share token from keygen output
      --signing-public string   Ed25519 signing public key (base64)

Global Flags:
      --debug   enable diagnostic logs to stderr
```

### ende encrypt --help

```text
Encrypt and sign secret payload

Usage:
  ende encrypt [flags]

Aliases:
  encrypt, enc

Flags:
      --binary           output raw binary envelope
  -h, --help             help for encrypt
  -i, --in string        input path or - (default "-")
  -o, --out string       output path or - (default "-")
      --prompt           prompt for secret value interactively
  -s, --sign-as string   local signing key id (optional if default signer is set)
      --text             output ASCII-armored envelope for copy/paste transport (default true) (default true)
  -t, --to strings       recipient alias, github:user, or age1... public key

Global Flags:
      --debug   enable diagnostic logs to stderr
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
      --text-out          print decrypted plaintext to stdout
      --verify-required   require signature verification (default true)

Global Flags:
      --debug   enable diagnostic logs to stderr
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

Global Flags:
      --debug   enable diagnostic logs to stderr
```
