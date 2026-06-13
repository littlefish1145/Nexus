package services

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"

	"nexus/internal/services/token_service"
)

// TokenIssuer defines the interface for token issuance used by the coordinator.
// Both the local TokenService and GRPCTokenService implement this interface.
type TokenIssuer interface {
	IssueWriteToken(ctx context.Context, userID, bucket, objectKey string, ttlSeconds int64) (*token_service.DelegationToken, error)
	IssueReadToken(ctx context.Context, userID, bucket, objectKey, contentHash string, ttlSeconds int64) (*token_service.DelegationToken, error)
	IssueDeleteToken(ctx context.Context, userID, bucket, objectKey string, ttlSeconds int64) (*token_service.DelegationToken, error)
	Close() error
}

// EncryptionCoordinator coordinates all crypto microservices
// Main service uses this to orchestrate encryption/decryption operations
type EncryptionCoordinator struct {
	tokenService     TokenIssuer
	keyGenService    KeyGenerator
	keyUnwrapService KeyUnwrapper
	encryptService   DataEncryptor
	decryptService   DataDecryptor
	keyStoreService  KeyStorer
	opaClient        *OPAClient
}

// CoordinatorConfig configuration for the coordinator
type CoordinatorConfig struct {
	TokenService     TokenIssuer
	KeyGenService    KeyGenerator
	KeyUnwrapService KeyUnwrapper
	EncryptService   DataEncryptor
	DecryptService   DataDecryptor
	KeyStoreService  KeyStorer
	OPAClient        *OPAClient
}

// NewEncryptionCoordinator creates a new encryption coordinator
func NewEncryptionCoordinator(cfg CoordinatorConfig) *EncryptionCoordinator {
	return &EncryptionCoordinator{
		tokenService:     cfg.TokenService,
		keyGenService:    cfg.KeyGenService,
		keyUnwrapService: cfg.KeyUnwrapService,
		encryptService:   cfg.EncryptService,
		decryptService:   cfg.DecryptService,
		keyStoreService:  cfg.KeyStoreService,
		opaClient:        cfg.OPAClient,
	}
}

// EncryptOperation performs a complete encryption operation
// Returns ciphertext reader, keyID, nonce+authTag metadata, ciphertext size, error
func (c *EncryptionCoordinator) EncryptOperation(ctx context.Context, userID, bucket, objectKey string, plaintext io.Reader, objectSize int64) (io.Reader, string, []byte, int64, error) {
	// Step 1: Policy decision via OPA
	if c.opaClient != nil {
		allowed, err := c.opaClient.EvaluateAccess(ctx, UserContext{
			ID: userID,
		}, ObjectContext{
			Bucket: bucket,
			Key:    objectKey,
			Size:   objectSize,
		}, ActionContext{
			Type:      "write",
			Operation: "encrypt_object",
		}, RequestContext{
			Time: time.Now(),
		})
		if err != nil {
			zap.L().Error("opa policy evaluation failed", zap.Error(err))
			return nil, "", nil, 0, fmt.Errorf("policy evaluation failed: %w", err)
		}
		if !allowed {
			return nil, "", nil, 0, fmt.Errorf("access denied by policy")
		}
	}

	// Step 2: Generate client ECDH key pair for session
	clientECDHPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", nil, 0, fmt.Errorf("failed to generate client ECDH key: %w", err)
	}
	clientECDHPub := clientECDHPriv.PublicKey()

	// Step 3: Request write token from TokenService
	writeToken, err := c.tokenService.IssueWriteToken(ctx, userID, bucket, objectKey, 30)
	if err != nil {
		return nil, "", nil, 0, fmt.Errorf("failed to issue write token: %w", err)
	}

	// Step 4: Generate DEK from KeyGenService
	encryptedDEK, ecdhEncryptedDEK, serviceECDHPub, err := c.keyGenService.GenerateDataKey(
		ctx,
		writeToken.TokenID,
		userID,
		bucket,
		objectKey,
		&ECDHPublicKey{
			PublicKey: clientECDHPub.Bytes(),
			Curve:     "P-256",
		},
	)
	if err != nil {
		return nil, "", nil, 0, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Step 5: Store encrypted DEK in KeyStoreService
	keyID, err := c.keyStoreService.StoreKey(bucket, objectKey, &EncryptedDEK{
		EncryptedKey: encryptedDEK.EncryptedKey,
		Algorithm:    encryptedDEK.Algorithm,
		KeyID:        encryptedDEK.KeyID,
		KeyVersion:   encryptedDEK.KeyVersion,
	}, objectSize)
	if err != nil {
		return nil, "", nil, 0, fmt.Errorf("failed to store key: %w", err)
	}

	// Step 6: Encrypt data with EncryptService
	plaintextData, err := io.ReadAll(plaintext)
	if err != nil {
		return nil, "", nil, 0, fmt.Errorf("failed to read plaintext: %w", err)
	}

	ciphertext, nonce, authTag, err := c.encryptService.Encrypt(
		clientECDHPriv,
		serviceECDHPub,
		ecdhEncryptedDEK,
		plaintextData,
		"AES-256-GCM",
	)
	if err != nil {
		return nil, "", nil, 0, fmt.Errorf("failed to encrypt data: %w", err)
	}

	zap.L().Info("encryption completed",
		zap.String("key_id", keyID),
		zap.String("bucket", bucket),
		zap.String("object_key", objectKey),
		zap.Int("plaintext_size", len(plaintextData)),
		zap.Int("ciphertext_size", len(ciphertext)))

	// Combine nonce and authTag for storage
	metadata := append(nonce, authTag...)

	return io.NopCloser(bytes.NewReader(ciphertext)), keyID, metadata, int64(len(ciphertext)), nil
}

// DecryptOperation performs a complete decryption operation
func (c *EncryptionCoordinator) DecryptOperation(ctx context.Context, userID, bucket, objectKey string, ciphertext io.Reader, keyID string, metadata []byte) (io.Reader, error) {
	// Step 1: Policy decision via OPA
	if c.opaClient != nil {
		allowed, err := c.opaClient.EvaluateAccess(ctx, UserContext{
			ID: userID,
		}, ObjectContext{
			Bucket: bucket,
			Key:    objectKey,
		}, ActionContext{
			Type:      "read",
			Operation: "decrypt_object",
		}, RequestContext{
			Time: time.Now(),
		})
		if err != nil {
			zap.L().Error("opa policy evaluation failed", zap.Error(err))
			return nil, fmt.Errorf("policy evaluation failed: %w", err)
		}
		if !allowed {
			return nil, fmt.Errorf("access denied by policy")
		}
	}

	// Step 2: Generate client ECDH key pair for session
	clientECDHPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ECDH key: %w", err)
	}
	clientECDHPub := clientECDHPriv.PublicKey()

	// Step 3: Request read token from TokenService
	readToken, err := c.tokenService.IssueReadToken(ctx, userID, bucket, objectKey, "", 30)
	if err != nil {
		return nil, fmt.Errorf("failed to issue read token: %w", err)
	}

	// Step 4: Get encrypted DEK from KeyStoreService
	encryptedDEK, err := c.keyStoreService.GetKey(bucket, objectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Step 5: Unwrap DEK from KeyUnwrapService
	ecdhEncryptedDEK, serviceECDHPub, err := c.keyUnwrapService.UnwrapKey(
		ctx,
		readToken.TokenID,
		userID,
		bucket,
		objectKey,
		encryptedDEK,
		&ECDHPublicKey{
			PublicKey: clientECDHPub.Bytes(),
			Curve:     "P-256",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	// Step 6: Decrypt data with DecryptService
	ciphertextData, err := io.ReadAll(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	// Parse metadata (nonce + authTag)
	nonceLen := 12
	authTagLen := 16
	if len(metadata) < nonceLen+authTagLen {
		return nil, fmt.Errorf("invalid metadata: too short")
	}
	nonce := metadata[:nonceLen]
	authTag := metadata[nonceLen : nonceLen+authTagLen]

	plaintext, err := c.decryptService.Decrypt(
		clientECDHPriv,
		serviceECDHPub,
		ecdhEncryptedDEK,
		ciphertextData,
		nonce,
		authTag,
		"AES-256-GCM",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	zap.L().Info("decryption completed",
		zap.String("key_id", encryptedDEK.KeyID),
		zap.String("bucket", bucket),
		zap.String("object_key", objectKey),
		zap.Int("ciphertext_size", len(ciphertextData)),
		zap.Int("plaintext_size", len(plaintext)))

	return io.NopCloser(bytes.NewReader(plaintext)), nil
}

// DeleteKey deletes the key for an object
func (c *EncryptionCoordinator) DeleteKey(ctx context.Context, userID, bucket, objectKey string) error {
	// Step 1: Policy decision via OPA
	if c.opaClient != nil {
		allowed, err := c.opaClient.EvaluateAccess(ctx, UserContext{
			ID: userID,
		}, ObjectContext{
			Bucket: bucket,
			Key:    objectKey,
		}, ActionContext{
			Type:      "delete",
			Operation: "delete_object",
		}, RequestContext{
			Time: time.Now(),
		})
		if err != nil {
			return fmt.Errorf("policy evaluation failed: %w", err)
		}
		if !allowed {
			return fmt.Errorf("access denied by policy")
		}
	}

	// Step 2: Request delete token
	deleteToken, err := c.tokenService.IssueDeleteToken(ctx, userID, bucket, objectKey, 30)
	if err != nil {
		return fmt.Errorf("failed to issue delete token: %w", err)
	}

	// Step 3: Delete key from KeyStoreService
	if err := c.keyStoreService.DeleteKey(bucket, objectKey); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	zap.L().Info("key deleted",
		zap.String("token_id", deleteToken.TokenID),
		zap.String("bucket", bucket),
		zap.String("object_key", objectKey))

	return nil
}

// EncryptWithClientKey encrypts data using a customer-provided key (SSE-C).
// The client key is used directly as the DEK (no envelope encryption).
// Returns ciphertext reader, nonce+authTag metadata, ciphertext size, error.
// The client key is NEVER persisted.
func (c *EncryptionCoordinator) EncryptWithClientKey(ctx context.Context, plaintext io.Reader, clientKey []byte, objectSize int64) (io.Reader, []byte, int64, error) {
	if len(clientKey) != 32 {
		return nil, nil, 0, fmt.Errorf("invalid client key size: expected 32 bytes, got %d", len(clientKey))
	}

	block, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	plaintextData, err := io.ReadAll(plaintext)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to read plaintext: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintextData, nil)

	// Split ciphertext and authTag: GCM authTag is the last 16 bytes of the sealed output
	authTagLen := 16
	if len(ciphertext) < authTagLen {
		return nil, nil, 0, fmt.Errorf("ciphertext too short")
	}
	authTag := ciphertext[len(ciphertext)-authTagLen:]
	pureCiphertext := ciphertext[:len(ciphertext)-authTagLen]

	// Combine nonce and authTag for metadata storage (same pattern as EncryptOperation)
	metadata := append(nonce, authTag...)

	zap.L().Info("sse-c encryption completed",
		zap.Int("plaintext_size", len(plaintextData)),
		zap.Int("ciphertext_size", len(pureCiphertext)))

	return io.NopCloser(bytes.NewReader(pureCiphertext)), metadata, int64(len(pureCiphertext)), nil
}

// DecryptWithClientKey decrypts data using a customer-provided key (SSE-C).
// The client key is used directly as the DEK.
func (c *EncryptionCoordinator) DecryptWithClientKey(ctx context.Context, ciphertext io.Reader, clientKey []byte, metadata []byte, objectSize int64) (io.Reader, error) {
	if len(clientKey) != 32 {
		return nil, fmt.Errorf("invalid client key size: expected 32 bytes, got %d", len(clientKey))
	}

	block, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Parse metadata (nonce + authTag)
	nonceLen := gcm.NonceSize()
	authTagLen := 16
	if len(metadata) < nonceLen+authTagLen {
		return nil, fmt.Errorf("invalid metadata: too short")
	}
	nonce := metadata[:nonceLen]
	authTag := metadata[nonceLen : nonceLen+authTagLen]

	ciphertextData, err := io.ReadAll(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	// Reconstruct the full GCM sealed data: ciphertext || authTag
	gcmData := append(ciphertextData, authTag...)

	plaintext, err := gcm.Open(nil, nonce, gcmData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	zap.L().Info("sse-c decryption completed",
		zap.Int("ciphertext_size", len(ciphertextData)),
		zap.Int("plaintext_size", len(plaintext)))

	return io.NopCloser(bytes.NewReader(plaintext)), nil
}

// ComputeSSECKeySHA256 computes the SHA-256 hash of a client key for storage verification.
func ComputeSSECKeySHA256(clientKey []byte) string {
	h := sha256.Sum256(clientKey)
	return fmt.Sprintf("%x", h[:])
}

// Close closes all services
func (c *EncryptionCoordinator) Close() error {
	var errs []error

	if c.tokenService != nil {
		if err := c.tokenService.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.keyGenService != nil {
		if err := c.keyGenService.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.keyUnwrapService != nil {
		if err := c.keyUnwrapService.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.encryptService != nil {
		if err := c.encryptService.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.decryptService != nil {
		if err := c.decryptService.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.keyStoreService != nil {
		if err := c.keyStoreService.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing services: %v", errs)
	}

	return nil
}
