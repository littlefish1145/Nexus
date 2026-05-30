package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"nexus/internal/common"

	"go.uber.org/zap"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrInvalidToken         = errors.New("invalid or expired token")
	ErrEncryptionFailed     = errors.New("encryption failed")
	ErrDecryptionFailed     = errors.New("decryption failed")
	ErrKeyNotFound          = errors.New("encryption key not found")
	ErrInvalidKeySize       = errors.New("invalid key size")
	ErrInvalidCiphertext    = errors.New("invalid ciphertext")
	ErrNonceReadFailed      = errors.New("nonce read failed")
	ErrCiphertextReadFailed = errors.New("ciphertext read failed")
	ErrDecryptionAuthFail   = errors.New("decryption failed (authentication error)")
)

type SecureByteSlice struct {
	data []byte
	mu   sync.Mutex
}

func NewSecureByteSlice(size int) *SecureByteSlice {
	return &SecureByteSlice{
		data: make([]byte, size),
	}
}

func NewSecureByteSliceFrom(data []byte) *SecureByteSlice {
	secure := &SecureByteSlice{
		data: make([]byte, len(data)),
	}
	copy(secure.data, data)

	runtime.SetFinalizer(secure, func(s *SecureByteSlice) {
		s.zero()
	})

	return secure
}

func (s *SecureByteSlice) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

func (s *SecureByteSlice) zero() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data {
		s.data[i] = 0
	}
}

func (s *SecureByteSlice) Destroy() {
	s.zero()
	s.data = nil
}

type DataEncryptionKey struct {
	Key    *SecureByteSlice
	KeyID  string
	Expiry time.Time
}

func (d *DataEncryptionKey) IsExpired() bool {
	return time.Now().After(d.Expiry)
}

func (d *DataEncryptionKey) Destroy() {
	if d.Key != nil {
		d.Key.Destroy()
	}
}

type KMS interface {
	RequestWriteToken(ctx context.Context, userID, bucket, objectKey string) (*common.KMSDelegationToken, error)
	RequestReadToken(ctx context.Context, userID, bucket, objectKey, contentHash string) (*common.KMSDelegationToken, error)
	RequestDeleteToken(ctx context.Context, userID, bucket, objectKey string) (*common.KMSDelegationToken, error)
	GenerateDataKey(ctx context.Context, token *common.KMSDelegationToken) (plaintextDEK []byte, encryptedDEK *EncryptedDEK, err error)
	UnwrapKey(ctx context.Context, token *common.KMSDelegationToken, encryptedDEK *EncryptedDEK) ([]byte, error)
	CheckDedup(ctx context.Context, contentHash string) (bool, string, error)
	Close() error
}

func deriveEd25519KeyPair(masterKey []byte, info string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	hkdfReader := hkdf.New(sha256.New, masterKey, nil, []byte(info))
	pubKey, privKey, err := ed25519.GenerateKey(hkdfReader)
	return privKey, pubKey, err
}

func verifyTokenSignature(token *common.KMSDelegationToken, pubKey ed25519.PublicKey, expectedType common.TokenType) error {
	if err := token.Verify(pubKey); err != nil {
		zap.L().Warn("kms audit", zap.String("operation", "token_verify_failed"), zap.String("token_id", token.TokenID), zap.Error(err))
		return ErrInvalidToken
	}
	if token.TokenType != expectedType {
		zap.L().Warn("kms audit", zap.String("operation", "token_verify_failed"), zap.String("token_id", token.TokenID), zap.String("reason", "wrong_token_type"))
		return ErrInvalidToken
	}
	return nil
}

type LocalKMS struct {
	mu             sync.RWMutex
	masterKey      []byte
	signingPrivKey ed25519.PrivateKey
	signingPubKey  ed25519.PublicKey
	dedupIndex     map[string]string
}

func NewLocalKMS(masterKeyPath string) (*LocalKMS, error) {
	var masterKey []byte

	if masterKeyPath != "" {
		if keyData, err := os.ReadFile(masterKeyPath); err == nil && len(keyData) >= 32 {
			masterKey = keyData[:32]
		}
	}

	if masterKey == nil {
		masterKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
			return nil, fmt.Errorf("failed to generate master key: %w", err)
		}

		if masterKeyPath != "" {
			if err := os.MkdirAll(filepath.Dir(masterKeyPath), 0700); err != nil {
				return nil, fmt.Errorf("failed to create key directory: %w", err)
			}
			if err := os.WriteFile(masterKeyPath, masterKey, 0600); err != nil {
				return nil, fmt.Errorf("failed to save master key: %w", err)
			}
		}
	}

	privKey, pubKey, err := deriveEd25519KeyPair(masterKey, "nexus-ed25519-seed")
	if err != nil {
		return nil, fmt.Errorf("failed to derive signing key: %w", err)
	}

	kms := &LocalKMS{
		masterKey:      masterKey,
		signingPrivKey: privKey,
		signingPubKey:  pubKey,
		dedupIndex:     make(map[string]string),
	}

	runtime.SetFinalizer(kms, func(k *LocalKMS) {
		for i := range k.masterKey {
			k.masterKey[i] = 0
		}
	})

	return kms, nil
}

func (k *LocalKMS) deriveKEK(bucket, objectKey, domain string) []byte {
	h := hmac.New(sha256.New, k.masterKey)
	h.Write([]byte(bucket))
	h.Write([]byte{0x00})
	h.Write([]byte(objectKey))
	h.Write([]byte{0x00})
	h.Write([]byte(domain))
	return h.Sum(nil)
}

func (k *LocalKMS) RequestWriteToken(ctx context.Context, userID, bucket, objectKey string) (*common.KMSDelegationToken, error) {
	token := &common.KMSDelegationToken{
		TokenID:    generateTokenID(),
		TokenType:  common.TokenTypeWrite,
		UserID:     userID,
		Bucket:     bucket,
		ObjectKey:  objectKey,
		Expiry:     time.Now().Add(30 * time.Second),
		CreatedAt:  time.Now(),
		Operations: []string{"encrypt"},
	}

	if err := token.Sign(k.signingPrivKey); err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	zap.L().Info("kms audit", zap.String("operation", "token_issued"), zap.String("token_type", "write"), zap.String("user_id", userID), zap.String("bucket", bucket))

	return token, nil
}

func (k *LocalKMS) RequestReadToken(ctx context.Context, userID, bucket, objectKey, contentHash string) (*common.KMSDelegationToken, error) {
	token := &common.KMSDelegationToken{
		TokenID:     generateTokenID(),
		TokenType:   common.TokenTypeRead,
		UserID:      userID,
		Bucket:      bucket,
		ObjectKey:   objectKey,
		ContentHash: contentHash,
		Expiry:      time.Now().Add(30 * time.Second),
		CreatedAt:   time.Now(),
		Operations:  []string{"decrypt"},
	}

	if err := token.Sign(k.signingPrivKey); err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	zap.L().Info("kms audit", zap.String("operation", "token_issued"), zap.String("token_type", "read"), zap.String("user_id", userID), zap.String("bucket", bucket))

	return token, nil
}

func (k *LocalKMS) RequestDeleteToken(ctx context.Context, userID, bucket, objectKey string) (*common.KMSDelegationToken, error) {
	token := &common.KMSDelegationToken{
		TokenID:    generateTokenID(),
		TokenType:  common.TokenTypeDelete,
		UserID:     userID,
		Bucket:     bucket,
		ObjectKey:  objectKey,
		Expiry:     time.Now().Add(30 * time.Second),
		CreatedAt:  time.Now(),
		Operations: []string{"delete"},
	}

	if err := token.Sign(k.signingPrivKey); err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	zap.L().Info("kms audit", zap.String("operation", "token_issued"), zap.String("token_type", "delete"), zap.String("user_id", userID), zap.String("bucket", bucket))

	return token, nil
}

func (k *LocalKMS) GenerateDataKey(ctx context.Context, token *common.KMSDelegationToken) ([]byte, *EncryptedDEK, error) {
	if err := verifyTokenSignature(token, k.signingPubKey, common.TokenTypeWrite); err != nil {
		return nil, nil, err
	}

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	kek := k.deriveKEK(token.Bucket, token.ObjectKey, "nexus-kek-encrypt-v1")
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	kekGCM, err := newGCMWrapper(kek)
	if err != nil {
		return nil, nil, err
	}

	encryptedDEKBytes, err := kekGCM.Encrypt(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	encryptedDEK := &EncryptedDEK{
		EncryptedKey: encryptedDEKBytes,
		Algorithm:    "AES-256-GCM",
		KeyID:        generateTokenID(),
	}

	zap.L().Info("kms audit", zap.String("operation", "data_key_generated"), zap.String("bucket", token.Bucket), zap.String("object_key", token.ObjectKey))

	return dek, encryptedDEK, nil
}

func (k *LocalKMS) UnwrapKey(ctx context.Context, token *common.KMSDelegationToken, encryptedDEK *EncryptedDEK) ([]byte, error) {
	if err := verifyTokenSignature(token, k.signingPubKey, common.TokenTypeRead); err != nil {
		return nil, err
	}

	kek := k.deriveKEK(token.Bucket, token.ObjectKey, "nexus-kek-decrypt-v1")
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	kekGCM, err := newGCMWrapper(kek)
	if err != nil {
		return nil, err
	}

	dekBytes, err := kekGCM.Decrypt(encryptedDEK.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	zap.L().Info("kms audit", zap.String("operation", "key_unwrapped"), zap.String("bucket", token.Bucket), zap.String("object_key", token.ObjectKey))

	return dekBytes, nil
}

func (k *LocalKMS) CheckDedup(ctx context.Context, contentHash string) (bool, string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if existingDEK, exists := k.dedupIndex[contentHash]; exists {
		return true, existingDEK, nil
	}

	return false, "", nil
}

func (k *LocalKMS) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	for i := range k.masterKey {
		k.masterKey[i] = 0
	}

	return nil
}

type VaultKMS struct {
	mu             sync.RWMutex
	addr           string
	token          string
	transitKey     string
	signingPrivKey ed25519.PrivateKey
	signingPubKey  ed25519.PublicKey
	httpClient     *http.Client
	dedupIndex     map[string]string
}

func NewVaultKMS(addr, token, transitKey string) (*VaultKMS, error) {
	privKey, pubKey, err := deriveEd25519KeyPair([]byte(token), "nexus-vault-ed25519-seed")
	if err != nil {
		return nil, fmt.Errorf("failed to derive signing key: %w", err)
	}

	kms := &VaultKMS{
		addr:           addr,
		token:          token,
		transitKey:     transitKey,
		signingPrivKey: privKey,
		signingPubKey:  pubKey,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		dedupIndex:     make(map[string]string),
	}

	return kms, nil
}

func (k *VaultKMS) RequestWriteToken(ctx context.Context, userID, bucket, objectKey string) (*common.KMSDelegationToken, error) {
	token := &common.KMSDelegationToken{
		TokenID:    generateTokenID(),
		TokenType:  common.TokenTypeWrite,
		UserID:     userID,
		Bucket:     bucket,
		ObjectKey:  objectKey,
		Expiry:     time.Now().Add(30 * time.Second),
		CreatedAt:  time.Now(),
		Operations: []string{"encrypt"},
	}

	if err := token.Sign(k.signingPrivKey); err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	zap.L().Info("kms audit", zap.String("operation", "token_issued"), zap.String("token_type", "write"), zap.String("user_id", userID), zap.String("bucket", bucket))

	return token, nil
}

func (k *VaultKMS) RequestReadToken(ctx context.Context, userID, bucket, objectKey, contentHash string) (*common.KMSDelegationToken, error) {
	token := &common.KMSDelegationToken{
		TokenID:     generateTokenID(),
		TokenType:   common.TokenTypeRead,
		UserID:      userID,
		Bucket:      bucket,
		ObjectKey:   objectKey,
		ContentHash: contentHash,
		Expiry:      time.Now().Add(30 * time.Second),
		CreatedAt:   time.Now(),
		Operations:  []string{"decrypt"},
	}

	if err := token.Sign(k.signingPrivKey); err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	zap.L().Info("kms audit", zap.String("operation", "token_issued"), zap.String("token_type", "read"), zap.String("user_id", userID), zap.String("bucket", bucket))

	return token, nil
}

func (k *VaultKMS) RequestDeleteToken(ctx context.Context, userID, bucket, objectKey string) (*common.KMSDelegationToken, error) {
	token := &common.KMSDelegationToken{
		TokenID:    generateTokenID(),
		TokenType:  common.TokenTypeDelete,
		UserID:     userID,
		Bucket:     bucket,
		ObjectKey:  objectKey,
		Expiry:     time.Now().Add(30 * time.Second),
		CreatedAt:  time.Now(),
		Operations: []string{"delete"},
	}

	if err := token.Sign(k.signingPrivKey); err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	zap.L().Info("kms audit", zap.String("operation", "token_issued"), zap.String("token_type", "delete"), zap.String("user_id", userID), zap.String("bucket", bucket))

	return token, nil
}

func (k *VaultKMS) GenerateDataKey(ctx context.Context, token *common.KMSDelegationToken) ([]byte, *EncryptedDEK, error) {
	if err := verifyTokenSignature(token, k.signingPubKey, common.TokenTypeWrite); err != nil {
		return nil, nil, err
	}

	reqBody := vaultGenerateDataKeyRequest{
		Type: "plaintext",
		Bits: 256,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/transit/generate-data-key/%s", k.addr, k.transitKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", k.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("vault returned status %d", resp.StatusCode)
	}

	var vaultResp vaultGenerateDataKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return nil, nil, fmt.Errorf("failed to decode vault response: %w", err)
	}

	plaintextDEK, err := base64.StdEncoding.DecodeString(vaultResp.Data.Plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode plaintext DEK: %w", err)
	}

	encryptedDEK := &EncryptedDEK{
		EncryptedKey: []byte(vaultResp.Data.Ciphertext),
		Algorithm:    "AES-256-GCM",
		KeyID:        generateTokenID(),
		KeyVersion:   vaultResp.Data.KeyVersion,
	}

	zap.L().Info("kms audit", zap.String("operation", "data_key_generated"), zap.String("bucket", token.Bucket), zap.String("object_key", token.ObjectKey), zap.Int("key_version", vaultResp.Data.KeyVersion))

	return plaintextDEK, encryptedDEK, nil
}

func (k *VaultKMS) UnwrapKey(ctx context.Context, token *common.KMSDelegationToken, encryptedDEK *EncryptedDEK) ([]byte, error) {
	if err := verifyTokenSignature(token, k.signingPubKey, common.TokenTypeRead); err != nil {
		return nil, err
	}

	reqBody := vaultDecryptRequest{
		Ciphertext: string(encryptedDEK.EncryptedKey),
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/transit/decrypt/%s", k.addr, k.transitKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", k.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned status %d", resp.StatusCode)
	}

	var vaultResp vaultDecryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return nil, fmt.Errorf("failed to decode vault response: %w", err)
	}

	plaintextDEK, err := base64.StdEncoding.DecodeString(vaultResp.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext DEK: %w", err)
	}

	zap.L().Info("kms audit", zap.String("operation", "key_unwrapped"), zap.String("bucket", token.Bucket), zap.String("object_key", token.ObjectKey))

	return plaintextDEK, nil
}

func (k *VaultKMS) CheckDedup(ctx context.Context, contentHash string) (bool, string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if existingDEK, exists := k.dedupIndex[contentHash]; exists {
		return true, existingDEK, nil
	}

	return false, "", nil
}

func (k *VaultKMS) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.httpClient.CloseIdleConnections()
	return nil
}

type vaultGenerateDataKeyRequest struct {
	Type string `json:"type"`
	Bits int    `json:"bits"`
}

type vaultGenerateDataKeyResponse struct {
	Data struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
		KeyVersion int    `json:"key_version"`
	} `json:"data"`
}

type vaultDecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type vaultDecryptResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
}

type EncryptedDEK struct {
	EncryptedKey []byte
	Algorithm    string
	KeyID        string
	KeyVersion   int
}

type EncryptionService struct {
	mu           sync.RWMutex
	kms          KMS
	gcm          *gcmWrapper
	dedupEnabled bool
}

type gcmWrapper struct {
	key []byte
}

func newGCMWrapper(key []byte) (*gcmWrapper, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}
	return &gcmWrapper{key: key}, nil
}

func (g *gcmWrapper) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(g.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (g *gcmWrapper) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(g.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func NewEncryptionService(kms KMS, enableDedup bool) (*EncryptionService, error) {
	return &EncryptionService{
		kms:          kms,
		dedupEnabled: enableDedup,
	}, nil
}

func (e *EncryptionService) Encrypt(ctx context.Context, userID, bucket, objectKey string, plaintext io.Reader) (io.Reader, *EncryptedDEK, error) {
	token, err := e.kms.RequestWriteToken(ctx, userID, bucket, objectKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request write token: %w", err)
	}

	dek, encryptedDEK, err := e.kms.GenerateDataKey(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	return e.StreamEncryptWithDEK(dek, plaintext), encryptedDEK, nil
}

func (e *EncryptionService) StreamEncryptWithDEK(dek []byte, plaintext io.Reader) io.Reader {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return io.MultiReader()
	}

	gcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return io.MultiReader()
	}

	nonce := make([]byte, gcmCipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return io.MultiReader()
	}

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		if _, err := pw.Write(nonce); err != nil {
			return
		}

		data, err := io.ReadAll(io.LimitReader(plaintext, 5<<30))
		if err != nil {
			pw.CloseWithError(fmt.Errorf("failed to read plaintext: %w", err))
			return
		}

		encrypted := gcmCipher.Seal(nil, nonce, data, nil)
		if _, err := pw.Write(encrypted); err != nil {
			return
		}
	}()

	return pr
}

func (e *EncryptionService) Decrypt(ctx context.Context, token *common.KMSDelegationToken, encryptedDEK *EncryptedDEK, ciphertext io.Reader) (io.Reader, error) {
	dekBytes, err := e.kms.UnwrapKey(ctx, token, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}
	defer func() {
		for i := range dekBytes {
			dekBytes[i] = 0
		}
	}()

	return e.StreamDecrypt(ciphertext, dekBytes)
}

func (e *EncryptionService) StreamEncrypt(ctx context.Context, userID, bucket, objectKey string, plaintext io.Reader, size int64) (io.Reader, *EncryptedDEK, error) {
	token, err := e.kms.RequestWriteToken(ctx, userID, bucket, objectKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request write token: %w", err)
	}

	dek, encryptedDEK, err := e.kms.GenerateDataKey(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcmCipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		defer func() {
			if r := recover(); r != nil {
				pw.CloseWithError(fmt.Errorf("encryption panic: %v", r))
			}
		}()

		if _, err := pw.Write(nonce); err != nil {
			return
		}

		data, err := io.ReadAll(io.LimitReader(plaintext, 5<<30))
		if err != nil {
			pw.CloseWithError(fmt.Errorf("failed to read plaintext: %w", err))
			return
		}

		encrypted := gcmCipher.Seal(nil, nonce, data, nil)
		if _, err := pw.Write(encrypted); err != nil {
			return
		}
	}()

	return pr, encryptedDEK, nil
}

func (e *EncryptionService) StreamDecrypt(ciphertext io.Reader, dek []byte) (io.Reader, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcmCipher.NonceSize()

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(ciphertext, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNonceReadFailed, err)
	}

	encryptedData, err := io.ReadAll(io.LimitReader(ciphertext, 5<<30))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCiphertextReadFailed, err)
	}

	plaintext, err := gcmCipher.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionAuthFail, err)
	}

	return bytes.NewReader(plaintext), nil
}

func (e *EncryptionService) ValidateEncryptedDEK(ctx context.Context, userID, bucket, objectKey string, encryptedDEK *EncryptedDEK) error {
	token, err := e.kms.RequestReadToken(ctx, userID, bucket, objectKey, "")
	if err != nil {
		return fmt.Errorf("failed to request read token for DEK validation: %w", err)
	}

	dekBytes, err := e.kms.UnwrapKey(ctx, token, encryptedDEK)
	if err != nil {
		return fmt.Errorf("encrypted DEK validation failed: %w", err)
	}
	defer func() {
		for i := range dekBytes {
			dekBytes[i] = 0
		}
	}()

	if len(dekBytes) != 32 {
		return fmt.Errorf("encrypted DEK validation failed: invalid DEK size %d", len(dekBytes))
	}

	return nil
}

func (e *EncryptionService) Close() error {
	return e.kms.Close()
}

func (e *EncryptionService) GetKMS() KMS {
	return e.kms
}

func computeHash(r io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func generateTokenID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: unable to generate token ID")
	}
	return base64.URLEncoding.EncodeToString(b)
}
