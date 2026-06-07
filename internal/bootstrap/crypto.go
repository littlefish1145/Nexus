package bootstrap

import (
	"fmt"

	"nexus/internal/config"
	"nexus/internal/services"
	"nexus/internal/services/token_service"
	"nexus/internal/services/keygen_service"
	"nexus/internal/services/keyunwrap_service"
	"nexus/internal/services/encrypt_service"
	"nexus/internal/services/decrypt_service"
	"nexus/internal/services/keystore_service"
)

// InitializeCryptoServices creates an EncryptionCoordinator based on config.
// In distributed mode, it uses gRPC clients to call remote services.
// In local mode, it creates service instances in-process.
func InitializeCryptoServices(cfg *config.Config) (*services.EncryptionCoordinator, error) {
	if !cfg.CryptoServices.Enabled {
		return nil, fmt.Errorf("crypto services not enabled")
	}

	if cfg.CryptoServices.DistributedMode {
		return initializeDistributed(cfg)
	}
	return initializeLocal(cfg)
}

// initializeLocal creates all services in-process
func initializeLocal(cfg *config.Config) (*services.EncryptionCoordinator, error) {
	keyPath := cfg.CryptoServices.KeyPath
	if keyPath == "" {
		keyPath = "./data/keys"
	}
	keyStorePath := cfg.CryptoServices.KeyStorePath
	if keyStorePath == "" {
		keyStorePath = "./data/keystore"
	}
	auditSize := cfg.CryptoServices.AuditSize
	if auditSize <= 0 {
		auditSize = 10000
	}

	tokenSvc, err := token_service.NewTokenService(token_service.TokenServiceConfig{
		KeyPath:   keyPath + "/token",
		AuditSize: auditSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token service: %w", err)
	}

	keyGenSvc, err := keygen_service.NewKeyGenService(keygen_service.KeyGenServiceConfig{
		KeyPath:   keyPath + "/keygen",
		CurveName: "P-256",
		AuditSize: auditSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keygen service: %w", err)
	}

	keyUnwrapSvc, err := keyunwrap_service.NewKeyUnwrapService(keyunwrap_service.KeyUnwrapServiceConfig{
		KeyPath:   keyPath + "/keygen",
		AuditSize: auditSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keyunwrap service: %w", err)
	}

	encryptSvc := encrypt_service.NewEncryptService(encrypt_service.EncryptServiceConfig{
		AuditSize: auditSize,
	})

	decryptSvc := decrypt_service.NewDecryptService(decrypt_service.DecryptServiceConfig{
		AuditSize: auditSize,
	})

	keyStoreSvc, err := keystore_service.NewKeyStoreService(keystore_service.KeyStoreServiceConfig{
		DataPath:  keyStorePath,
		AuditSize: auditSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keystore service: %w", err)
	}

	var opaClient *services.OPAClient
	if cfg.CryptoServices.OPAAddress != "" {
		opaClient = services.NewOPAClient(services.OPAConfig{
			Address: cfg.CryptoServices.OPAAddress,
		})
	}

	return services.NewEncryptionCoordinator(services.CoordinatorConfig{
		TokenService:     tokenSvc,
		KeyGenService:    keyGenSvc,
		KeyUnwrapService: keyUnwrapSvc,
		EncryptService:   encryptSvc,
		DecryptService:   decryptSvc,
		KeyStoreService:  keyStoreSvc,
		OPAClient:        opaClient,
	}), nil
}

// initializeDistributed creates gRPC clients for remote services
func initializeDistributed(cfg *config.Config) (*services.EncryptionCoordinator, error) {
	var opaClient *services.OPAClient
	if cfg.CryptoServices.OPAAddress != "" {
		opaClient = services.NewOPAClient(services.OPAConfig{
			Address: cfg.CryptoServices.OPAAddress,
		})
	}

	tokenAddr := cfg.CryptoServices.TokenServiceAddr
	if tokenAddr == "" {
		tokenAddr = "localhost:50051"
	}
	keygenAddr := cfg.CryptoServices.KeyGenServiceAddr
	if keygenAddr == "" {
		keygenAddr = "localhost:50052"
	}
	keyunwrapAddr := cfg.CryptoServices.KeyUnwrapServiceAddr
	if keyunwrapAddr == "" {
		keyunwrapAddr = "localhost:50053"
	}
	encryptAddr := cfg.CryptoServices.EncryptServiceAddr
	if encryptAddr == "" {
		encryptAddr = "localhost:50054"
	}
	decryptAddr := cfg.CryptoServices.DecryptServiceAddr
	if decryptAddr == "" {
		decryptAddr = "localhost:50055"
	}
	keystoreAddr := cfg.CryptoServices.KeyStoreServiceAddr
	if keystoreAddr == "" {
		keystoreAddr = "localhost:50056"
	}

	return services.NewDistributedCoordinator(
		tokenAddr,
		keygenAddr,
		keyunwrapAddr,
		encryptAddr,
		decryptAddr,
		keystoreAddr,
		opaClient,
		nil,
	)
}
