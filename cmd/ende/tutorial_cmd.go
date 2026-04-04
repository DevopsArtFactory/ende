package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/kuma/ende/internal/crypto"
	"github.com/kuma/ende/internal/keyring"
	"github.com/kuma/ende/internal/sign"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ANSI color helpers
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorGray    = "\033[90m"
	colorBgBlack = "\033[40m"
	colorWhite   = "\033[97m"
)

func bold(s string) string   { return colorBold + s + colorReset }
func cyan(s string) string   { return colorCyan + s + colorReset }
func green(s string) string  { return colorGreen + s + colorReset }
func yellow(s string) string { return colorYellow + s + colorReset }
func gray(s string) string   { return colorGray + s + colorReset }
func highlight(s string) string {
	return colorBold + colorBgBlack + colorWhite + "  " + s + "  " + colorReset
}

type tutorialLang struct {
	selectLang        string
	welcome           string
	step              string
	keygen            string
	keygenOption      string
	keygenOpt1        string
	keygenOpt2        string
	keygenNameHint    string
	keygenCmd         string
	keygenDone        string
	keygenExistDone   string
	keygenNotFound    string
	keygenShareLabel  string
	register          string
	registerOption    string
	registerOpt1      string
	registerOpt2      string
	registerDesc      string
	registerShareHint string
	registerExists    string
	registerUnreg     string
	registerRetry     string
	registerOk        string
	registerSkipped   string
	registerPeerName  string
	registerPeerShare string
	encryptTitle      string
	encryptDesc       string
	encryptToHint     string
	encryptSignHint   string
	encryptTo         string
	encryptSignAs     string
	encryptOut        string
	encryptCmd        string
	encryptPolicy     string
	encryptPolicy1    string
	encryptPolicy2    string
	encryptPolicy3    string
	encryptInput      string
	encryptOk         string
	encryptSkipped    string
	decryptTitle      string
	decryptDesc       string
	decryptInHint     string
	decryptCmd        string
	decryptOk         string
	decryptSkipped    string
	done              string
	pressEnter        string
	inputName         string
	inputShare        string
}

var langs = map[string]tutorialLang{
	"en": {
		selectLang:        "Select language / 언어 선택 [en/kr]: ",
		welcome:           "=== Ende Tutorial ===",
		step:              "Step",
		keygen:            "Set up your sender key (you are the sender in this tutorial)",
		keygenOption:      "How do you want to set up your sender key?",
		keygenOpt1:        "  [1] Generate a new key",
		keygenOpt2:        "  [2] Use an existing key",
		keygenNameHint:    "  --name is the identity used between sender and recipient (e.g. -t, --sign-as).",
		keygenCmd:         "  ende key keygen --name <your-name> --export-public",
		keygenDone:        "Key generated. Share the token below with your peer:",
		keygenExistDone:   "Key found. Share the token below with your peer:",
		keygenNotFound:    "Key not found. Please check the name with `ende key list`.",
		keygenShareLabel:  "  share: ",
		register:          "Register a peer (recipient)",
		registerOption:    "How do you want to register the peer?",
		registerOpt1:      "  [1] Paste peer's share token (peer already has a key)",
		registerOpt2:      "  [2] Generate a key for the peer now (local test)",
		registerDesc:      "Paste the peer's share token to register them as a recipient and trusted sender.",
		registerShareHint: "  The share token is the 'share:' value printed during the peer's keygen.",
		registerExists:    "Already registered? Remove first:",
		registerUnreg:     "  ende unregister <alias>",
		registerRetry:     "Then run register again.",
		registerOk:        "Registered peer: ",
		registerSkipped:   "No token entered, skipping registration.",
		registerPeerName:  "Enter peer key name: ",
		registerPeerShare: "Peer's share token: ",
		encryptTitle:      "Encrypt a secret",
		encryptDesc:       "Encrypt plaintext and sign it with your key.",
		encryptToHint:     "  -t      : the alias registered in Step 2 (the recipient)",
		encryptSignHint:   "  --sign-as: your key name from Step 1 (the sender)",
		encryptTo:         "  -t <alias>        recipient alias",
		encryptSignAs:     "  --sign-as <sender-name>  your local key name",
		encryptOut:        "  -o <file>         output file",
		encryptCmd:        "  echo 'SECRET=value' | ende encrypt -t <alias> --sign-as <sender-name> -o secret.txt",
		encryptPolicy:     "Password policy (choose one):",
		encryptPolicy1:    "  [1] min 8 chars,  upper + lower + special + digit",
		encryptPolicy2:    "  [2] min 12 chars, upper + lower + digit",
		encryptPolicy3:    "  [3] pwgen: pwgen -1 -N 3 -s -y -r '[/@\"]' 20",
		encryptInput:      "Enter secret to encrypt (or press Enter to skip): ",
		encryptOk:         "Encrypted and saved to: ",
		encryptSkipped:    "Skipping encryption practice.",
		decryptTitle:      "Decrypt a secret",
		decryptDesc:       "Decrypt the envelope file produced in Step 3.",
		decryptInHint:     "  -i is the encrypted file from Step 3, -o is the output plaintext file.",
		decryptCmd:        "  ende decrypt -i secret.txt -o decrypted.txt",
		decryptOk:         "Decrypted result: ",
		decryptSkipped:    "No encrypted file from Step 3, skipping.",
		done:              "Tutorial complete. Happy encrypting!",
		pressEnter:        "  [Press Enter to continue]",
		inputName:         "Enter your key name: ",
		inputShare:        "Enter peer's share token (ENDE-PUB-1:...) or press Enter to skip: ",
	},
	"kr": {
		selectLang:        "Select language / 언어 선택 [en/kr]: ",
		welcome:           "=== Ende 튜토리얼 ===",
		step:              "단계",
		keygen:            "송신자 키 설정 (이 튜토리얼에서 나는 송신자입니다)",
		keygenOption:      "송신자 키 설정 방법을 선택하세요:",
		keygenOpt1:        "  [1] 새 키 생성",
		keygenOpt2:        "  [2] 기존 키 사용",
		keygenNameHint:    "  --name은 송신자와 수신자 간 식별에 사용되는 이름입니다 (예: -t, --sign-as).",
		keygenCmd:         "  ende key keygen --name <이름> --export-public",
		keygenDone:        "키가 생성됐습니다. 아래 토큰을 상대방에게 전달하세요:",
		keygenExistDone:   "키를 찾았습니다. 아래 토큰을 상대방에게 전달하세요:",
		keygenNotFound:    "키를 찾을 수 없습니다. `ende key list`로 이름을 확인하세요.",
		keygenShareLabel:  "  share: ",
		register:          "상대방 등록 (수신자)",
		registerOption:    "상대방 등록 방법을 선택하세요:",
		registerOpt1:      "  [1] 상대방 share 토큰 입력 (상대방이 이미 키를 가진 경우)",
		registerOpt2:      "  [2] 상대방 키를 직접 생성해서 등록 (로컬 테스트용)",
		registerDesc:      "상대방의 share 토큰을 붙여넣으면 수신자 및 신뢰 발신자로 자동 등록됩니다.",
		registerShareHint: "  share 토큰은 상대방이 keygen 시 출력된 'share:' 값입니다.",
		registerExists:    "이미 등록된 경우 먼저 제거하세요:",
		registerUnreg:     "  ende unregister <alias>",
		registerRetry:     "그 다음 다시 register를 실행하세요.",
		registerOk:        "등록 완료: ",
		registerSkipped:   "토큰 미입력, 등록을 건너뜁니다.",
		registerPeerName:  "상대방 키 이름을 입력하세요: ",
		registerPeerShare: "상대방 share 토큰: ",
		encryptTitle:      "비밀 암호화",
		encryptDesc:       "평문을 암호화하고 내 키로 서명합니다.",
		encryptToHint:     "  -t      : 단계 2에서 등록한 상대방 alias (수신자)",
		encryptSignHint:   "  --sign-as: 단계 1에서 생성한 내 키 이름 (발신자)",
		encryptTo:         "  -t <alias>              수신자 alias",
		encryptSignAs:     "  --sign-as <송신자 이름>  내 로컬 키 이름",
		encryptOut:        "  -o <파일>               출력 파일",
		encryptCmd:        "  echo 'SECRET=value' | ende encrypt -t <alias> --sign-as <송신자 이름> -o secret.txt",
		encryptPolicy:     "비밀번호 정책 (하나 선택):",
		encryptPolicy1:    "  [1] 8자 이상,  대소문자 + 특수문자 + 숫자 포함",
		encryptPolicy2:    "  [2] 12자 이상, 대소문자 + 숫자 포함",
		encryptPolicy3:    "  [3] pwgen 기준: pwgen -1 -N 3 -s -y -r '[/@\"]' 20",
		encryptInput:      "암호화할 비밀을 입력하세요 (Enter로 건너뛰기): ",
		encryptOk:         "암호화 완료, 저장 위치: ",
		encryptSkipped:    "암호화 실습을 건너뜁니다.",
		decryptTitle:      "비밀 복호화",
		decryptDesc:       "단계 3에서 만든 암호화 파일을 복호화합니다.",
		decryptInHint:     "  -i는 단계 3의 암호화 파일, -o는 복호화 결과 파일입니다.",
		decryptCmd:        "  ende decrypt -i secret.txt -o decrypted.txt",
		decryptOk:         "복호화 결과: ",
		decryptSkipped:    "단계 3의 암호화 파일이 없어 건너뜁니다.",
		done:              "튜토리얼 완료. 안전하게 사용하세요!",
		pressEnter:        "  [Enter 키를 눌러 계속]",
		inputName:         "키 이름을 입력하세요: ",
		inputShare:        "상대방 share 토큰을 입력하세요 (ENDE-PUB-1:...) 또는 Enter로 건너뛰기: ",
	},
}

func newTutorialCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "tutorial",
		Short: "Interactive step-by-step guide for ende",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTutorial(cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}

func runTutorial(in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)

	fmt.Fprint(out, langs["en"].selectLang)
	choice, _ := r.ReadString('\n')
	choice = strings.TrimSpace(choice)
	l, ok := langs[choice]
	if !ok {
		l = langs["en"]
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, bold(cyan(l.welcome)))

	// Step 1: keygen
	fmt.Fprintf(out, "\n%s %s\n", bold(yellow(fmt.Sprintf("[%s 1]", l.step))), bold(l.keygen))
	fmt.Fprintln(out, l.keygenOption)
	fmt.Fprintln(out, cyan(l.keygenOpt1))
	fmt.Fprintln(out, cyan(l.keygenOpt2))
	fmt.Fprint(out, cyan("  > "))
	keyChoice, _ := r.ReadString('\n')
	keyChoice = strings.TrimSpace(keyChoice)

	fmt.Fprintln(out, gray(l.keygenNameHint))
	fmt.Fprint(out, cyan(l.inputName))
	myName, _ := r.ReadString('\n')
	myName = strings.TrimSpace(myName)

	var myShare string
	var err error
	if keyChoice == "2" {
		// Use existing key — just derive share token
		store, err := keyring.Load()
		if err != nil || myName == "" {
			fmt.Fprintf(out, gray("  (load failed: %v)\n"), err)
		} else if entry, ok := store.Key(myName); !ok {
			fmt.Fprintln(out, yellow(l.keygenNotFound))
		} else {
			myShare, err = tutorialShareFromEntry(entry)
			if err != nil {
				fmt.Fprintf(out, gray("  (share failed: %v)\n"), err)
			} else {
				fmt.Fprintln(out, green(l.keygenExistDone))
				fmt.Fprintln(out, bold(l.keygenShareLabel+myShare))
			}
		}
	} else {
		fmt.Fprintln(out, gray(l.keygenCmd))
		myShare, err = tutorialKeygen(myName)
		if err != nil {
			fmt.Fprintf(out, gray("  (keygen skipped: %v)\n"), err)
		} else {
			fmt.Fprintln(out, green(l.keygenDone))
			fmt.Fprintln(out, bold(l.keygenShareLabel+myShare))
		}
	}
	pause(out, r, gray(l.pressEnter))

	// Step 2: register
	fmt.Fprintf(out, "\n%s %s\n", bold(yellow(fmt.Sprintf("[%s 2]", l.step))), bold(l.register))
	fmt.Fprintln(out, l.registerOption)
	fmt.Fprintln(out, cyan(l.registerOpt1))
	fmt.Fprintln(out, cyan(l.registerOpt2))
	fmt.Fprint(out, cyan("  > "))
	regChoice, _ := r.ReadString('\n')
	regChoice = strings.TrimSpace(regChoice)

	var peerName string
	switch regChoice {
	case "2":
		fmt.Fprint(out, cyan(l.registerPeerName))
		pn, _ := r.ReadString('\n')
		peerName = strings.TrimSpace(pn)
		peerShare, err := tutorialKeygen(peerName)
		if err != nil {
			fmt.Fprintf(out, gray("  (keygen failed: %v)\n"), err)
			peerName = ""
		} else {
			fmt.Fprintln(out, bold(l.registerPeerShare+peerShare))
			if err := tutorialRegister(peerShare); err != nil {
				fmt.Fprintf(out, gray("  (register failed: %v)\n"), err)
				peerName = ""
			} else {
				fmt.Fprintln(out, green(l.registerOk+peerName))
			}
		}
	default:
		fmt.Fprintln(out, l.registerDesc)
		fmt.Fprintln(out, gray(l.registerShareHint))
		fmt.Fprintln(out)
		fmt.Fprintln(out, yellow(l.registerExists))
		fmt.Fprintln(out, gray(l.registerUnreg))
		fmt.Fprintln(out, gray(l.registerRetry))
		fmt.Fprint(out, cyan(l.inputShare))
		ps, _ := r.ReadString('\n')
		ps = strings.TrimSpace(ps)
		if ps != "" {
			if err := tutorialRegister(ps); err != nil {
				fmt.Fprintf(out, gray("  (register failed: %v)\n"), err)
			} else {
				p, _ := decodeShareToken(ps)
				peerName = p.ID
				fmt.Fprintln(out, green(l.registerOk+peerName))
			}
		} else {
			fmt.Fprintln(out, gray(l.registerSkipped))
		}
	}
	pause(out, r, gray(l.pressEnter))

	// Step 3: encrypt
	fmt.Fprintf(out, "\n%s %s\n", bold(yellow(fmt.Sprintf("[%s 3]", l.step))), bold(l.encryptTitle))
	fmt.Fprintln(out, l.encryptDesc)
	fmt.Fprintln(out, cyan(l.encryptToHint))
	fmt.Fprintln(out, cyan(l.encryptSignHint))
	fmt.Fprintln(out)
	fmt.Fprintln(out, gray(l.encryptTo))
	fmt.Fprintln(out, gray(l.encryptSignAs))
	fmt.Fprintln(out, gray(l.encryptOut))
	fmt.Fprintln(out, highlight(l.encryptCmd))
	fmt.Fprintln(out)
	fmt.Fprintln(out, yellow(l.encryptPolicy))
	fmt.Fprintln(out, gray(l.encryptPolicy1))
	fmt.Fprintln(out, gray(l.encryptPolicy2))
	fmt.Fprintln(out, gray(l.encryptPolicy3))
	fmt.Fprintln(out)

	var encryptedFile string
	fmt.Fprint(out, cyan(l.encryptInput))
	var secret string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(out)
		if err == nil {
			secret = string(b)
		}
	} else {
		s, _ := r.ReadString('\n')
		secret = strings.TrimRight(s, "\r\n")
	}
	if secret != "" && myName != "" && peerName != "" {
		encryptedFile, err = tutorialEncrypt([]byte(secret), peerName, myName)
		if err != nil {
			fmt.Fprintf(out, gray("  (encrypt failed: %v)\n"), err)
		} else {
			fmt.Fprintln(out, green(l.encryptOk+encryptedFile))
		}
	} else {
		fmt.Fprintln(out, gray(l.encryptSkipped))
	}
	pause(out, r, gray(l.pressEnter))

	// Step 4: decrypt
	fmt.Fprintf(out, "\n%s %s\n", bold(yellow(fmt.Sprintf("[%s 4]", l.step))), bold(l.decryptTitle))
	fmt.Fprintln(out, l.decryptDesc)
	fmt.Fprintln(out, gray(l.decryptInHint))
	fmt.Fprintln(out, highlight(l.decryptCmd))
	fmt.Fprintln(out)
	if encryptedFile != "" {
		plaintext, err := tutorialDecrypt(encryptedFile)
		if err != nil {
			fmt.Fprintf(out, gray("  (decrypt failed: %v)\n"), err)
		} else {
			fmt.Fprintln(out, green(l.decryptOk)+bold(string(plaintext)))
		}
	} else {
		fmt.Fprintln(out, gray(l.decryptSkipped))
	}
	pause(out, r, gray(l.pressEnter))

	fmt.Fprintln(out)
	fmt.Fprintln(out, bold(green(l.done)))
	return nil
}

func tutorialEncrypt(plaintext []byte, recipientAlias, signerName string) (string, error) {
	store, err := keyring.Load()
	if err != nil {
		return "", err
	}
	rcpt, ok := store.Recipient(recipientAlias)
	if !ok {
		return "", fmt.Errorf("recipient not found: %s", recipientAlias)
	}
	ageRcpt, err := age.ParseX25519Recipient(rcpt.AgePublic)
	if err != nil {
		return "", err
	}
	keyEntry, ok := store.Key(signerName)
	if !ok {
		return "", fmt.Errorf("signer key not found: %s", signerName)
	}
	signPrivBytes, err := os.ReadFile(keyEntry.SignPrivate)
	if err != nil {
		return "", err
	}
	envelope, err := crypto.Seal(plaintext, []age.Recipient{ageRcpt}, signerName, keyEntry.SignPublic, strings.TrimSpace(string(signPrivBytes)), []string{recipientAlias})
	if err != nil {
		return "", err
	}
	envelope = crypto.EncodeTextEnvelope(envelope)
	f, err := os.CreateTemp("", "ende-tutorial-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(envelope); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func tutorialDecrypt(encryptedFile string) ([]byte, error) {
	store, err := keyring.Load()
	if err != nil {
		return nil, err
	}
	envelopeBytes, err := os.ReadFile(encryptedFile)
	if err != nil {
		return nil, err
	}
	identities, err := loadIdentities(store)
	if err != nil {
		return nil, err
	}
	_, plaintext, err := crypto.Open(envelopeBytes, identities, true)
	return plaintext, err
}

// tutorialKeygen generates a key pair and returns the share token.
func tutorialKeygen(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("name is empty")
	}
	store, err := keyring.Load()
	if err != nil {
		return "", err
	}
	if _, exists := store.Key(name); exists {
		entry, _ := store.Key(name)
		return tutorialShareFromEntry(entry)
	}
	_, _, keysDir, err := keyring.DefaultPaths()
	if err != nil {
		return "", err
	}
	xid, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	signPub, signPriv, err := sign.GenerateKeyPair()
	if err != nil {
		return "", err
	}
	agePath := filepath.Join(keysDir, name+".agekey")
	signPath := filepath.Join(keysDir, name+".signkey")
	if err := os.WriteFile(agePath, []byte(xid.String()+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(signPath, []byte(signPriv+"\n"), 0o600); err != nil {
		return "", err
	}
	store.AddKey(keyring.KeyEntry{
		ID:          name,
		AgeIdentity: agePath,
		SignPrivate: signPath,
		SignPublic:  signPub,
	})
	if err := store.AddSender(name, signPub, "local-key", "", true); err != nil {
		return "", err
	}
	if err := store.Save(); err != nil {
		return "", err
	}
	return encodeShareToken(name, xid.Recipient().String(), signPub)
}

func tutorialShareFromEntry(entry keyring.KeyEntry) (string, error) {
	raw, err := os.ReadFile(entry.AgeIdentity)
	if err != nil {
		return "", err
	}
	xid, err := age.ParseX25519Identity(strings.TrimSpace(string(raw)))
	if err != nil {
		return "", err
	}
	return encodeShareToken(entry.ID, xid.Recipient().String(), entry.SignPublic)
}

// tutorialRegister registers a peer from a share token.
func tutorialRegister(shareToken string) error {
	p, err := decodeShareToken(shareToken)
	if err != nil {
		return err
	}
	if _, err := age.ParseX25519Recipient(p.Recipient); err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	if _, err := sign.ParsePublicKey(p.SigningPublic); err != nil {
		return fmt.Errorf("invalid signing key: %w", err)
	}
	store, err := keyring.Load()
	if err != nil {
		return err
	}
	if err := store.AddRecipient(p.ID, p.Recipient, "register", p.ID, true); err != nil {
		return err
	}
	if err := store.AddSender(p.ID, p.SigningPublic, "register", p.ID, true); err != nil {
		return err
	}
	return store.Save()
}

func pause(out io.Writer, r *bufio.Reader, msg string) {
	fmt.Fprintln(out, msg)
	r.ReadString('\n')
}
