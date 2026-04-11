package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"golang.org/x/term"
)

var isTerminal = term.IsTerminal
var readPassword = term.ReadPassword

type fdReader interface {
	io.Reader
	Fd() uintptr
}

func promptRecipientInput(in io.Reader, errw io.Writer) (alias string, keyOrShare string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "peer alias: ")
	alias, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read alias: %w", err)
	}
	fmt.Fprint(errw, "peer public key or share code: ")
	keyOrShare, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read key/share: %w", err)
	}
	return strings.TrimSpace(alias), strings.TrimSpace(keyOrShare), nil
}

func readPromptSecret(in io.Reader, errw io.Writer) ([]byte, error) {
	fmt.Fprint(errw, "secret> ")

	if tty, ok := in.(fdReader); ok && isTerminal(int(tty.Fd())) {
		v, err := readPassword(int(tty.Fd()))
		fmt.Fprintln(errw)
		if err != nil {
			return nil, fmt.Errorf("read prompt value: %w", err)
		}
		secret := strings.TrimRight(string(v), "\r\n")
		if secret == "" {
			return nil, fmt.Errorf("secret is required")
		}
		return []byte(secret), nil
	}

	r := bufio.NewReader(in)
	v, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read prompt value: %w", err)
	}
	secret := strings.TrimRight(v, "\r\n")
	if secret == "" {
		return nil, fmt.Errorf("secret is required")
	}
	return []byte(secret), nil
}

func promptRegisterInput(in io.Reader, errw io.Writer) (alias string, recipientOrShare string, signingPublic string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "alias: ")
	alias, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read alias: %w", err)
	}
	fmt.Fprint(errw, "peer public key or share code: ")
	recipientOrShare, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read recipient/share: %w", err)
	}
	trimmed := strings.TrimSpace(recipientOrShare)
	if strings.HasPrefix(trimmed, sharePrefix) {
		return strings.TrimSpace(alias), trimmed, "", nil
	}
	fmt.Fprint(errw, "signing public key: ")
	signingPublic, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read signing public: %w", err)
	}
	return strings.TrimSpace(alias), trimmed, strings.TrimSpace(signingPublic), nil
}

func readEnvelopeInteractive(in io.Reader, errw io.Writer) ([]byte, error) {
	fmt.Fprintln(errw, "Paste encrypted envelope, then press Enter:")
	var buf strings.Builder
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		buf.WriteString(line)
		buf.WriteString("\n")
		if strings.TrimSpace(line) == "-----END ENDE ENVELOPE-----" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read envelope: %w", err)
	}
	result := buf.String()
	if result == "" {
		return nil, fmt.Errorf("read envelope: empty input")
	}
	return []byte(result), nil
}

func promptShareRegisterInput(in io.Reader, errw io.Writer) (share string, aliasOverride string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "share code (ENDE-PUB-1:...): ")
	share, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read share code: %w", err)
	}
	share = strings.TrimSpace(share)
	if share == "" {
		return "", "", fmt.Errorf("share code is required")
	}
	fmt.Fprint(errw, "peer name override (optional, Enter to use the shared name): ")
	aliasOverride, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read alias override: %w", err)
	}
	return share, strings.TrimSpace(aliasOverride), nil
}
