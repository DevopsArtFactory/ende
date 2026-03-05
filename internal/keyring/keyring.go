package keyring

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kuma/ende/internal/diag"
	"gopkg.in/yaml.v3"
)

type RecipientEntry struct {
	Alias        string `yaml:"alias"`
	AgePublic    string `yaml:"age_public"`
	Fingerprint  string `yaml:"fingerprint"`
	Source       string `yaml:"source,omitempty"`
	Username     string `yaml:"username,omitempty"`
	GitHubSSHPin string `yaml:"github_ssh_pin,omitempty"`
}

type KeyEntry struct {
	ID          string `yaml:"id"`
	AgeIdentity string `yaml:"age_identity_file"`
	SignPrivate string `yaml:"sign_private_file"`
	SignPublic  string `yaml:"sign_public"`
}

type SenderEntry struct {
	ID          string `yaml:"id"`
	SignPublic  string `yaml:"sign_public"`
	Fingerprint string `yaml:"fingerprint"`
	Source      string `yaml:"source,omitempty"`
	Username    string `yaml:"username,omitempty"`
}

type File struct {
	Recipients map[string]RecipientEntry `yaml:"recipients"`
	Keys       map[string]KeyEntry       `yaml:"keys"`
	Senders    map[string]SenderEntry    `yaml:"senders,omitempty"`
	Defaults   Defaults                  `yaml:"defaults,omitempty"`
}

type Store struct {
	Path string
	Data File
}

type Defaults struct {
	SignerID string `yaml:"signer_id,omitempty"`
}

func DefaultPaths() (configDir, ringPath, keysDir string, err error) {
	if v := strings.TrimSpace(os.Getenv("ENDE_CONFIG_DIR")); v != "" {
		configDir = v
		ringPath = filepath.Join(configDir, "keyring.yaml")
		keysDir = filepath.Join(configDir, "keys")
		diag.Debugf("keyring.DefaultPaths: using ENDE_CONFIG_DIR=%s", configDir)
		return configDir, ringPath, keysDir, nil
	}
	if v := strings.TrimSpace(os.Getenv("ENDE_HOME")); v != "" {
		configDir = v
		ringPath = filepath.Join(configDir, "keyring.yaml")
		keysDir = filepath.Join(configDir, "keys")
		diag.Debugf("keyring.DefaultPaths: using ENDE_HOME=%s", configDir)
		return configDir, ringPath, keysDir, nil
	}
	if v := strings.TrimSpace(os.Getenv("VIRTUAL_ENV")); v != "" {
		configDir = filepath.Join(v, ".ende")
		ringPath = filepath.Join(configDir, "keyring.yaml")
		keysDir = filepath.Join(configDir, "keys")
		diag.Debugf("keyring.DefaultPaths: using VIRTUAL_ENV-derived dir=%s", configDir)
		return configDir, ringPath, keysDir, nil
	}
	if v := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); v != "" {
		configDir = filepath.Join(v, "ende")
		ringPath = filepath.Join(configDir, "keyring.yaml")
		keysDir = filepath.Join(configDir, "keys")
		diag.Debugf("keyring.DefaultPaths: using XDG_CONFIG_HOME=%s", configDir)
		return configDir, ringPath, keysDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		diag.Debugf("keyring.DefaultPaths: resolve home dir failed: %v", err)
		return "", "", "", fmt.Errorf("resolve home dir: %w", err)
	}
	configDir = filepath.Join(home, ".config", "ende")
	ringPath = filepath.Join(configDir, "keyring.yaml")
	keysDir = filepath.Join(configDir, "keys")
	diag.Debugf("keyring.DefaultPaths: config_dir=%s ring_path=%s keys_dir=%s", configDir, ringPath, keysDir)
	return configDir, ringPath, keysDir, nil
}

func EnsureDirs() error {
	configDir, _, keysDir, err := DefaultPaths()
	if err != nil {
		return err
	}
	diag.Debugf("keyring.EnsureDirs: ensure config dir %s", configDir)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		diag.Debugf("keyring.EnsureDirs: create config dir failed: %v", err)
		return fmt.Errorf("create config dir: %w", err)
	}
	diag.Debugf("keyring.EnsureDirs: ensure keys dir %s", keysDir)
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		diag.Debugf("keyring.EnsureDirs: create keys dir failed: %v", err)
		return fmt.Errorf("create keys dir: %w", err)
	}
	return nil
}

func Load() (*Store, error) {
	diag.Debugf("keyring.Load: start")
	if err := EnsureDirs(); err != nil {
		return nil, err
	}
	_, ringPath, _, err := DefaultPaths()
	if err != nil {
		return nil, err
	}
	st := &Store{Path: ringPath, Data: File{Recipients: map[string]RecipientEntry{}, Keys: map[string]KeyEntry{}, Senders: map[string]SenderEntry{}}}
	diag.Debugf("keyring.Load: reading keyring path=%s", ringPath)
	b, err := os.ReadFile(ringPath)
	if err != nil {
		if os.IsNotExist(err) {
			diag.Debugf("keyring.Load: keyring not found, returning empty in-memory store")
			return st, nil
		}
		diag.Debugf("keyring.Load: read failed: %v", err)
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	diag.Debugf("keyring.Load: bytes=%d", len(b))
	if err := yaml.Unmarshal(b, &st.Data); err != nil {
		diag.Debugf("keyring.Load: yaml parse failed: %v", err)
		return nil, fmt.Errorf("parse keyring yaml: %w", err)
	}
	if st.Data.Recipients == nil {
		st.Data.Recipients = map[string]RecipientEntry{}
	}
	if st.Data.Keys == nil {
		st.Data.Keys = map[string]KeyEntry{}
	}
	if st.Data.Senders == nil {
		st.Data.Senders = map[string]SenderEntry{}
	}
	diag.Debugf("keyring.Load: loaded keys=%d recipients=%d senders=%d", len(st.Data.Keys), len(st.Data.Recipients), len(st.Data.Senders))
	return st, nil
}

func (s *Store) Save() error {
	b, err := yaml.Marshal(&s.Data)
	if err != nil {
		diag.Debugf("keyring.Save: yaml marshal failed: %v", err)
		return fmt.Errorf("marshal keyring yaml: %w", err)
	}
	diag.Debugf("keyring.Save: writing path=%s bytes=%d", s.Path, len(b))
	if err := os.WriteFile(s.Path, b, 0o600); err != nil {
		diag.Debugf("keyring.Save: write failed: %v", err)
		return fmt.Errorf("write keyring: %w", err)
	}
	diag.Debugf("keyring.Save: success")
	return nil
}

func FingerprintAgePublicKey(pub string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(pub)))
	return hex.EncodeToString(sum[:])
}

func (s *Store) AddRecipient(alias, agePublic, source, username string, force bool) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	if _, exists := s.Data.Recipients[alias]; exists && !force {
		return fmt.Errorf("recipient alias %s already exists; use --force to overwrite", alias)
	}
	s.Data.Recipients[alias] = RecipientEntry{
		Alias:       alias,
		AgePublic:   strings.TrimSpace(agePublic),
		Fingerprint: FingerprintAgePublicKey(agePublic),
		Source:      source,
		Username:    username,
	}
	return nil
}

func (s *Store) Recipient(alias string) (RecipientEntry, bool) {
	r, ok := s.Data.Recipients[alias]
	return r, ok
}

func (s *Store) RemoveRecipient(alias string) bool {
	if _, ok := s.Data.Recipients[alias]; !ok {
		return false
	}
	delete(s.Data.Recipients, alias)
	return true
}

func (s *Store) AllRecipientAliases() []string {
	aliases := make([]string, 0, len(s.Data.Recipients))
	for a := range s.Data.Recipients {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	return aliases
}

func (s *Store) AddKey(entry KeyEntry) {
	s.Data.Keys[entry.ID] = entry
}

func (s *Store) Key(id string) (KeyEntry, bool) {
	k, ok := s.Data.Keys[id]
	return k, ok
}

func (s *Store) AllKeyIDs() []string {
	ids := make([]string, 0, len(s.Data.Keys))
	for id := range s.Data.Keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func FingerprintSignPublicKey(pub string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(pub)))
	return hex.EncodeToString(sum[:])
}

func (s *Store) AddSender(id, signPublic, source, username string, force bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("sender id is required")
	}
	if s.Data.Senders == nil {
		s.Data.Senders = map[string]SenderEntry{}
	}
	if _, exists := s.Data.Senders[id]; exists && !force {
		return fmt.Errorf("sender id %s already exists; use --force to overwrite", id)
	}
	s.Data.Senders[id] = SenderEntry{
		ID:          id,
		SignPublic:  strings.TrimSpace(signPublic),
		Fingerprint: FingerprintSignPublicKey(signPublic),
		Source:      source,
		Username:    username,
	}
	return nil
}

func (s *Store) Sender(id string) (SenderEntry, bool) {
	v, ok := s.Data.Senders[id]
	return v, ok
}

func (s *Store) RemoveSender(id string) bool {
	if _, ok := s.Data.Senders[id]; !ok {
		return false
	}
	delete(s.Data.Senders, id)
	return true
}

func (s *Store) AllSenderIDs() []string {
	ids := make([]string, 0, len(s.Data.Senders))
	for id := range s.Data.Senders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *Store) SetDefaultSigner(id string) error {
	if _, ok := s.Data.Keys[id]; !ok {
		return fmt.Errorf("unknown key id: %s", id)
	}
	s.Data.Defaults.SignerID = id
	return nil
}

func (s *Store) DefaultSigner() string {
	return strings.TrimSpace(s.Data.Defaults.SignerID)
}
