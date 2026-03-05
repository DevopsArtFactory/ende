package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func promptRecipientInput(in io.Reader, errw io.Writer) (alias string, keyOrShare string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "alias: ")
	alias, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read alias: %w", err)
	}
	fmt.Fprint(errw, "key/share: ")
	keyOrShare, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read key/share: %w", err)
	}
	return strings.TrimSpace(alias), strings.TrimSpace(keyOrShare), nil
}

func readPromptSecret(in io.Reader, errw io.Writer) ([]byte, error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "secret> ")
	v, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read prompt value: %w", err)
	}
	return []byte(strings.TrimRight(v, "\r\n")), nil
}

func promptRegisterInput(in io.Reader, errw io.Writer) (alias string, recipientOrShare string, signingPublic string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "alias: ")
	alias, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read alias: %w", err)
	}
	fmt.Fprint(errw, "recipient key or share token: ")
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

func promptShareRegisterInput(in io.Reader, errw io.Writer) (share string, aliasOverride string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "share token (ENDE-PUB-1:...): ")
	share, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read share token: %w", err)
	}
	share = strings.TrimSpace(share)
	if share == "" {
		return "", "", fmt.Errorf("share token is required")
	}
	fmt.Fprint(errw, "alias override (optional, Enter to use token id): ")
	aliasOverride, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read alias override: %w", err)
	}
	return share, strings.TrimSpace(aliasOverride), nil
}
