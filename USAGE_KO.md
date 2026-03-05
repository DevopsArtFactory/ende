# Ende CLI 사용 가이드 (보내는 사람/받는 사람 기준)

## 1. 개요
`ende`는 개발자 간 비밀값(토큰/비밀번호 등)을 평문 대신 암호문으로 전달하기 위한 CLI입니다.

핵심 보장:
- 수신자 공개키로 암호화되어 **수신자만 복호화 가능**
- 송신자 서명이 포함되어 **위조/변조 탐지 가능**
- 로컬 keyring을 신뢰 루트로 사용 (GitHub username은 선택 기능)

---

## 2. 초기 준비 (각자 1회)
각 개발자는 로컬에 자신의 키를 생성합니다.

```bash
./ende key keygen --name <내-ID>
```

예:
```bash
./ende key keygen --name alice
./ende key keygen --name bob
./ende key use --name alice
```

생성되는 항목:
- `~/.config/ende/keyring.yaml`
- `~/.config/ende/keys/<id>.agekey` (복호화용 개인키)
- `~/.config/ende/keys/<id>.signkey` (서명용 개인키)

---

## 3. 보내는 사람(Alice) 기준

### 3-1) 받는 사람(Bob)의 recipient 공개키 등록
Bob이 자신의 recipient 공개키를 전달하면 Alice가 alias로 등록합니다.

Bob 측 공개키 출력:
```bash
./ende key export --name bob --type recipient
```

Alice 측 등록:
```bash
./ende recipient add --alias bob --key "age1..."
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

중요:
- 기본값 `--verify-required=true`로 서명 검증 실패 시 복호화 실패.
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
- `ende key kg` = `ende key keygen`
- `ende key ls` = `ende key list`

## 6-1) key
### `ende key keygen`
로컬 키쌍 생성

옵션:
- `--name <id>`: 키 ID (필수)

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
- `-o, --out <path|->`: 출력(기본 `-` = stdout)

### `ende decrypt`
검증 + 복호화

옵션:
- `-i, --in <path|->`: 입력(기본 `-`)
- `-o, --out <path|->`: 평문 출력 경로 (`--out -`는 명시적으로만 허용)
- `--verify-required <bool>`: 서명 검증 강제 여부 (기본 `true`)

### `ende verify`
복호화 없이 서명 검증

옵션:
- `-i, --in <path|->`: 입력(기본 `-`)

---

## 7. 설계 시 고려한 보안 사항

- 신뢰 루트
  - 기본 신뢰 루트는 로컬 keyring에 pin된 공개키
  - GitHub username은 편의 기능이며 신뢰 루트가 아님

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
  - 평문 stdout 기본 차단 (`--out -` 명시 필요)
  - 개인키 파일 권한 `0600` 강제

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
