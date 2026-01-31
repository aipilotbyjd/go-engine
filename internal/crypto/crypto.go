package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrInvalidKey        = errors.New("invalid encryption key")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// Config holds encryption configuration
type Config struct {
	MasterKey          []byte
	KeyDerivationSalt  []byte
	KeyRotationEnabled bool
}

// Encryptor handles encryption and decryption of sensitive data
type Encryptor struct {
	masterKey []byte
	gcm       cipher.AEAD
}

// NewEncryptor creates a new encryptor with the given master key
func NewEncryptor(masterKey []byte) (*Encryptor, error) {
	if len(masterKey) < 16 {
		return nil, ErrInvalidKey
	}

	// Derive a 32-byte key for AES-256
	key := deriveKey(masterKey, nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Encryptor{
		masterKey: masterKey,
		gcm:       gcm,
	}, nil
}

// NewEncryptorFromString creates an encryptor from a base64-encoded key
func NewEncryptorFromString(keyStr string) (*Encryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		// Try hex encoding
		key, err = hex.DecodeString(keyStr)
		if err != nil {
			return nil, ErrInvalidKey
		}
	}
	return NewEncryptor(key)
}

// Encrypt encrypts plaintext and returns base64-encoded ciphertext
func (e *Encryptor) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// EncryptString encrypts a string
func (e *Encryptor) EncryptString(plaintext string) (string, error) {
	return e.Encrypt([]byte(plaintext))
}

// Decrypt decrypts base64-encoded ciphertext
func (e *Encryptor) Decrypt(ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// DecryptString decrypts to a string
func (e *Encryptor) DecryptString(ciphertext string) (string, error) {
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// CredentialStore stores encrypted credentials
type CredentialStore struct {
	encryptor   *Encryptor
	credentials map[string]string // encrypted values
}

// NewCredentialStore creates a new credential store
func NewCredentialStore(encryptor *Encryptor) *CredentialStore {
	return &CredentialStore{
		encryptor:   encryptor,
		credentials: make(map[string]string),
	}
}

// Set stores an encrypted credential
func (cs *CredentialStore) Set(key, value string) error {
	encrypted, err := cs.encryptor.EncryptString(value)
	if err != nil {
		return err
	}
	cs.credentials[key] = encrypted
	return nil
}

// Get retrieves and decrypts a credential
func (cs *CredentialStore) Get(key string) (string, error) {
	encrypted, exists := cs.credentials[key]
	if !exists {
		return "", errors.New("credential not found")
	}
	return cs.encryptor.DecryptString(encrypted)
}

// Delete removes a credential
func (cs *CredentialStore) Delete(key string) {
	delete(cs.credentials, key)
}

// Exists checks if a credential exists
func (cs *CredentialStore) Exists(key string) bool {
	_, exists := cs.credentials[key]
	return exists
}

// List returns all credential keys
func (cs *CredentialStore) List() []string {
	keys := make([]string, 0, len(cs.credentials))
	for k := range cs.credentials {
		keys = append(keys, k)
	}
	return keys
}

// Import imports encrypted credentials
func (cs *CredentialStore) Import(credentials map[string]string) {
	for k, v := range credentials {
		cs.credentials[k] = v
	}
}

// Export exports encrypted credentials
func (cs *CredentialStore) Export() map[string]string {
	result := make(map[string]string, len(cs.credentials))
	for k, v := range cs.credentials {
		result[k] = v
	}
	return result
}

// Hash functions

// HashSHA256 hashes data with SHA-256
func HashSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashPassword hashes a password with PBKDF2
func HashPassword(password, salt string) string {
	key := pbkdf2.Key([]byte(password), []byte(salt), 100000, 32, sha256.New)
	return hex.EncodeToString(key)
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, salt, expectedHash string) bool {
	hash := HashPassword(password, salt)
	return hash == expectedHash
}

// GenerateRandomBytes generates random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// GenerateRandomString generates a random string
func GenerateRandomString(n int) (string, error) {
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateMasterKey generates a new master key
func GenerateMasterKey() (string, error) {
	key, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// deriveKey derives a key from the master key using PBKDF2
func deriveKey(masterKey, salt []byte) []byte {
	if salt == nil {
		salt = []byte("linkflow-engine-v1")
	}
	return pbkdf2.Key(masterKey, salt, 10000, 32, sha256.New)
}
