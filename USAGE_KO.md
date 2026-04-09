# Ende CLI 사용 가이드 (보내는 사람/받는 사람 기준)

## 1. 개요
`ende`는 개발자 간 비밀값(토큰/비밀번호 등)을 평문 대신 암호문으로 전달하기 위한 CLI입니다.

핵심 보장:
- 수신자 공개키로 암호화되어 **수신자만 복호화 가능**
- 송신자 서명이 포함되어 **위조/변조 탐지 가능**
- 로컬 keyring을 신뢰 루트로 사용 (GitHub username은 선택 기능)
- 복호화 시 **신뢰된 송신자 pin**(`sender_key_id` + 서명 공개키 일치) 필수

## 설치 (Homebrew tap)
```bash
brew tap DevopsArtFactory/ende https://github.com/DevopsArtFactory/homebrew-ende
brew install ende
ende --version
```

## GitHub Release 바이너리 설치 (Linux / Windows)
`vX.Y.Z`를 실제 태그로 바꿔서 사용하세요.

Linux (아키텍처 자동 감지):
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

Windows (아키텍처 자동 감지, PowerShell):
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

## 2. 초기 준비 (각자 1회)
각 개발자는 로컬에 자신의 키를 생성합니다.

```bash
./ende key keygen --name <내-ID>
```

예:
```bash
./ende key keygen --name alice --export-public --export-dir .
./ende key keygen --name bob --export-public --export-dir .
```

`keygen` 출력의 `share:` 토큰을 상대에게 전달하면 됩니다.

생성되는 항목:
- `~/.config/ende/keyring.yaml`
- `~/.config/ende/keys/<id>.agekey` (복호화용 개인키)
- `~/.config/ende/keys/<id>.signkey` (서명용 개인키)

---

## 3. 보내는 사람(Alice) 기준

### 3-1) 받는 사람(Bob)의 recipient 공개키 등록
Bob이 자신의 recipient 공개키를 전달하면 Alice가 alias로 등록합니다.

Alice 측:
```bash
./ende key keygen --name alice
# 출력된 share: ENDE-PUB-1:... 복사
```

Bob 측(share 우선 대화형 등록):
```bash
./ende register
# share token (ENDE-PUB-1:...): ENDE-PUB-1:...
# alias override (optional, Enter to use token id):
```

### 3-2) 비밀값 암호화 + 서명
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob -o secret.ende
```

중요:
- `--sign-as`는 `ende key use`로 기본 송신자를 설정하지 않은 경우 필수입니다.
- `--to`는 여러 번 사용 가능(다중 수신자).

다중 수신자 예:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob -t diana -o secret.ende
```

### 3-3) 암호문 전달
생성된 `secret.ende` 파일만 전달합니다.

메신저/이메일 같은 텍스트 채널로 보낼 때:
```bash
echo 'TOKEN=abc123' | ./ende encrypt -t bob --text -o secret.txt
```

---

## 4. 받는 사람(Bob) 기준

### 4-1) 서명 검증(복호화 전)
```bash
./ende verify -i secret.ende
```

### 4-2) 복호화(기본: 검증 필수)
```bash
./ende decrypt -i secret.ende -o secret.txt
```

텍스트 envelope(armored) 입력도 지원:
```bash
./ende decrypt -i secret.txt -o secret.out
```

중요:
- 기본값 `--verify-required=true`로 서명 검증 실패 시 복호화 실패.
- 신뢰된 sender pin이 없으면 복호화 실패.
- 평문 stdout 출력은 기본 차단되며, 명시적으로 `--out -`를 줘야만 stdout 허용.

명시적 stdout 출력 예:
```bash
./ende decrypt -i secret.ende -o -
```

---

## 5. GitHub username 기반(선택)
기본 신뢰 모델은 로컬 keyring입니다. GitHub 기능은 보조 수단입니다.

등록 예:
```bash
./ende recipient add --github octocat --key "age1..." --key-index 0
```

동작:
- GitHub SSH 키를 조회해 pin(TOFU) 저장
- 이후 동일 alias 재등록 시 pin mismatch면 실패
- 실제 암호화 키는 `--key`로 주는 `age` recipient를 사용

---

## 6. 명령어 레퍼런스

### 명령어 alias (단축형)
- `ende enc` = `ende encrypt`
- `ende dec` = `ende decrypt`
- `ende v` = `ende verify`
- `ende k` = `ende key`
- `ende rcpt` = `ende recipient`
- `ende snd` = `ende sender`
- `ende reg` = `ende register`
- `ende key kg` = `ende key keygen`
- `ende key ls` = `ende key list`

## 6-1) key
### `ende key keygen`
로컬 키쌍 생성

옵션:
- `--name <id>`: 키 ID (필수)
- `--set-default <bool>`: 생성 키를 기본 송신자로 설정 (기본 `true`)
- `--export-public`: recipient/signing 공개키 파일로 export
- `--export-dir <path>`: 공개키 export 디렉터리
- `--export-prefix <name>`: export 파일명 prefix (기본 `--name`)

### `ende key export`
공개키 출력

옵션:
- `--name <id>`: 키 ID (필수)
- `--type recipient|signing-public`: 출력 타입 (필수)

### `ende key import`
recipient 공개키를 alias로 import

옵션:
- `--name <alias>`: recipient alias (필수)
- `--file <path>`: age recipient 키 파일 경로 (필수)

### `ende key list`
로컬 키/recipient 목록 출력

### `ende key use`
`encrypt` 기본 송신자 키 ID 설정

옵션:
- `--name <id>`: 키 ID
- positional 인자 `<id>`도 지원 (`ende key use alice`)

---

## 6-2) recipient
### `ende recipient add`
recipient 등록

옵션:
- `--alias <name>`: alias (로컬 등록 시 필수)
- `--key <age1...>`: age recipient 공개키 (필수)
- `--share <token>`: share 토큰(`ENDE-PUB-1:...`)으로 recipient+sender 자동 등록
- `--github <username>`: GitHub username (선택)
- `--key-index <n>`: GitHub SSH 키 pin 대상 index (기본 0)

### `ende recipient show <alias>`
recipient 상세 조회

### `ende recipient rotate <alias>`
recipient 키 교체

옵션:
- `--key <age1...>`: 새 recipient 공개키 (필수)

---

## 6-3) encrypt / decrypt / verify
### `ende encrypt`
암호화 + 서명

옵션:
- `-t, --to <alias|github:user|age1...>`: 수신자(복수 지정 가능, 필수)
- `-s, --sign-as <key-id>`: 송신자 서명 키 ID (기본 송신자 설정 시 생략 가능)
- `-i, --in <path|->`: 입력(기본 `-` = stdin)
- `-f, --file <path>`: 입력 파일 경로(`--in` 별칭)
- `-o, --out <path|->`: 출력(기본 `-` = stdout)
- `--text`: ASCII armor 출력 (기본 `true`)
- `--binary`: raw 바이너리 envelope 출력
- `--prompt`: 대화형으로 암호화할 값 입력

### `ende decrypt`
검증 + 복호화

옵션:
- `-i, --in <path|->`: 입력(기본 `-`)
- `-o, --out <path|->`: 평문 출력 경로 (`--out -`는 명시적으로만 허용)
- `--verify-required <bool>`: 서명 검증 강제 여부 (기본 `true`)
- `--text-out`: 복호화 평문을 stdout으로 출력

### `ende verify`
복호화 없이 서명 검증

옵션:
- `-i, --in <path|->`: 입력(기본 `-`)

---

## 6-4) sender
### `ende sender add`
신뢰할 송신자 서명 키 pin 등록

옵션:
- `--id <sender-id>`: 신뢰할 송신자 ID (필수)
- `--signing-public <base64>`: Ed25519 공개키 (필수)
- `--github <username>`: 선택 메타데이터
- `--force`: 기존 sender 덮어쓰기

### `ende sender show <id>`
신뢰된 송신자 상세 조회

### `ende sender rotate <id>`
신뢰된 송신자 서명 공개키 교체

옵션:
- `--signing-public <base64>`: 새 Ed25519 공개키 (필수)

### `ende sender list`
신뢰된 송신자 목록 출력

---

## 6-5) register
### `ende register`
recipient + trusted sender를 한 번에 등록

옵션:
- `--alias <name>`: 등록 alias
- `--share <token>`: share 토큰(`ENDE-PUB-1:...`) 원스텝 등록
- `--recipient-key <age1...>`: 수동 원스텝 등록용 recipient 키
- `--signing-public <base64>`: 수동 원스텝 등록용 서명 공개키
- `--force`: 기존 recipient/sender 엔트리 덮어쓰기

---

## 7. 설계 시 고려한 보안 사항

- 신뢰 루트
  - 기본 신뢰 루트는 로컬 keyring에 pin된 공개키
  - GitHub username은 편의 기능이며 신뢰 루트가 아님
  - sender ID -> 서명 공개키 pin을 복호화 시 강제 검증

- 암호 primitive 직접 구현 금지
  - `filippo.io/age` 사용
  - 자체 암호 알고리즘 구현/조합 회피

- 인증/무결성
  - Ed25519 서명 필수
  - 서명 대상: `ciphertext + canonical metadata(CBOR)`
  - 검증 먼저 수행해 변조/위조 조기 탐지

- 기본 안전 정책
  - `encrypt`에서 `--sign-as` 필수(단, 기본 송신자 설정 시 생략 가능)
  - `decrypt`에서 `verify-required=true` 기본
  - unknown sender ID는 복호화 단계에서 거부
  - 평문 stdout 기본 차단 (`--out -` 명시 필요)
  - Unix 계열에서는 개인키 파일 권한 `0600` 강제
  - Windows는 NTFS ACL이 `0600`과 직접 매핑되지 않아 POSIX 모드 검사를 생략

- 운영/감사 관점
  - 비밀값을 CLI 인자로 받지 않고 파일/stdin 중심 처리
  - 쉘 히스토리 유출 가능성 최소화

---

## 8. 권장 운영 절차
1. 팀 내 사용자별 키 ID 표준화 (`name` 규칙)
2. recipient 등록 시 fingerprint out-of-band 확인
3. 키 회전 주기 운영 (`recipient rotate`)
4. CI에서 `verify`/복호화 회귀 테스트 자동화

---

## 9. 자동 생성 `--help` 옵션
최신 옵션 표와 원본 help 출력은 아래 문서를 확인하세요.
- [CLI_HELP.md](/Users/kuma/Develop/opensource/ende/CLI_HELP.md)
