package keyring

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

type File struct {
	Recipients map[string]RecipientEntry `yaml:"recipients"`
	Keys       map[string]KeyEntry       `yaml:"keys"`
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
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", fmt.Errorf("resolve home dir: %w", err)
	}
	configDir = filepath.Join(home, ".config", "ende")
	ringPath = filepath.Join(configDir, "keyring.yaml")
	keysDir = filepath.Join(configDir, "keys")
	return configDir, ringPath, keysDir, nil
}

func EnsureDirs() error {
	configDir, _, keysDir, err := DefaultPaths()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}
	return nil
}

func Load() (*Store, error) {
	if err := EnsureDirs(); err != nil {
		return nil, err
	}
	_, ringPath, _, err := DefaultPaths()
	if err != nil {
		return nil, err
	}
	st := &Store{Path: ringPath, Data: File{Recipients: map[string]RecipientEntry{}, Keys: map[string]KeyEntry{}}}
	b, err := os.ReadFile(ringPath)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	if err := yaml.Unmarshal(b, &st.Data); err != nil {
		return nil, fmt.Errorf("parse keyring yaml: %w", err)
	}
	if st.Data.Recipients == nil {
		st.Data.Recipients = map[string]RecipientEntry{}
	}
	if st.Data.Keys == nil {
		st.Data.Keys = map[string]KeyEntry{}
	}
	return st, nil
}

func (s *Store) Save() error {
	b, err := yaml.Marshal(&s.Data)
	if err != nil {
		return fmt.Errorf("marshal keyring yaml: %w", err)
	}
	if err := os.WriteFile(s.Path, b, 0o600); err != nil {
		return fmt.Errorf("write keyring: %w", err)
	}
	return nil
}

func FingerprintAgePublicKey(pub string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(pub)))
	return hex.EncodeToString(sum[:])
}

func (s *Store) AddRecipient(alias, agePublic, source, username string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return fmt.Errorf("alias is required")
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
