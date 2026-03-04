package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// encryptedPatternPrefix is the prefix marker for "encrypted pattern values" in the config file.
//
// Design goals:
// - avoid writing plaintext keywords to disk (reduce accidental commits/copy leaks)
// - still match using plaintext in-process; the admin UI also shows plaintext
//
// Notes:
// - this only protects the "static config file contents"; anyone who can access the admin UI or process memory can still see plaintext
// - decryption depends on a runtime-injected key (derived from the CA private key by the caller)
const encryptedPatternPrefix = "__VG_ENC_V1__:"

type patternCrypto struct {
	gcm cipher.AEAD
}

func newPatternCrypto(key32 []byte) (*patternCrypto, error) {
	if len(key32) != 32 {
		return nil, fmt.Errorf("pattern encryption key must be 32 bytes, got %d", len(key32))
	}
	block, err := aes.NewCipher(key32)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &patternCrypto{gcm: gcm}, nil
}

func (c *patternCrypto) encryptString(plain string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("pattern crypto not configured")
	}
	if plain == "" {
		return "", nil
	}

	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := c.gcm.Seal(nil, nonce, []byte(plain), nil)
	raw := append(nonce, ciphertext...)
	return encryptedPatternPrefix + base64.RawStdEncoding.EncodeToString(raw), nil
}

func (c *patternCrypto) decryptMaybeEncrypted(s string) (plain string, wasEncrypted bool, err error) {
	if !strings.HasPrefix(s, encryptedPatternPrefix) {
		return s, false, nil
	}
	if c == nil {
		return "", true, fmt.Errorf("pattern crypto not configured")
	}
	b64 := strings.TrimPrefix(s, encryptedPatternPrefix)
	raw, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return "", true, fmt.Errorf("invalid base64: %w", err)
	}
	ns := c.gcm.NonceSize()
	if len(raw) < ns {
		return "", true, fmt.Errorf("ciphertext too short")
	}
	nonce := raw[:ns]
	ciphertext := raw[ns:]
	out, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", true, err
	}
	return string(out), true, nil
}

// SetPatternEncryptionKey enables "at-rest encryption" for persisted pattern values.
// key32 must be 32 bytes (AES-256).
//
// Note: this only configures the encryptor and does not rewrite the config file automatically;
// callers typically run Load() again afterwards to decrypt an already-loaded config.
func (m *Manager) SetPatternEncryptionKey(key32 []byte) error {
	if m == nil {
		return fmt.Errorf("config manager is nil")
	}
	c, err := newPatternCrypto(key32)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.patternCrypto = c
	m.mu.Unlock()
	return nil
}

func (m *Manager) decryptLoadedPatterns(cfg *Config) error {
	if m == nil || cfg == nil || m.patternCrypto == nil {
		return nil
	}

	for i := range cfg.Patterns.Keywords {
		v := cfg.Patterns.Keywords[i].Value
		plain, wasEnc, err := m.patternCrypto.decryptMaybeEncrypted(v)
		if err != nil {
			return fmt.Errorf("解密 keywords[%d] 失败：%w", i, err)
		}
		if wasEnc {
			cfg.Patterns.Keywords[i].Value = plain
		}
	}

	for i := range cfg.Patterns.Exclude {
		v := cfg.Patterns.Exclude[i]
		plain, wasEnc, err := m.patternCrypto.decryptMaybeEncrypted(v)
		if err != nil {
			return fmt.Errorf("解密 exclude[%d] 失败：%w", i, err)
		}
		if wasEnc {
			cfg.Patterns.Exclude[i] = plain
		}
	}

	return nil
}

func (m *Manager) encryptPatternsForSave(cfg Config) (Config, error) {
	if m == nil || m.patternCrypto == nil {
		return cfg, nil
	}

	// Note: cfg is a shallow copy and its slices share underlying arrays with the original;
	// deep-copy before mutating to avoid polluting the in-memory plaintext config.
	if len(cfg.Patterns.Keywords) > 0 {
		kw := append([]KeywordPattern(nil), cfg.Patterns.Keywords...)
		for i := range kw {
			enc, err := m.patternCrypto.encryptString(kw[i].Value)
			if err != nil {
				return Config{}, fmt.Errorf("加密 keywords[%d] 失败：%w", i, err)
			}
			kw[i].Value = enc
		}
		cfg.Patterns.Keywords = kw
	}

	if len(cfg.Patterns.Exclude) > 0 {
		ex := append([]string(nil), cfg.Patterns.Exclude...)
		for i := range ex {
			enc, err := m.patternCrypto.encryptString(ex[i])
			if err != nil {
				return Config{}, fmt.Errorf("加密 exclude[%d] 失败：%w", i, err)
			}
			ex[i] = enc
		}
		cfg.Patterns.Exclude = ex
	}

	return cfg, nil
}
