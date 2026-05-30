package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

type BackupManager struct {
	db            *bbolt.DB
	dataDir       string
	backupDir     string
	retentionDays []int
	mu            sync.Mutex
}

type BackupConfig struct {
	DataDir       string
	BackupDir     string
	RetentionDays []int
}

type BackupInfo struct {
	Name      string
	Path      string
	Size      int64
	CreatedAt time.Time
	Type      string
}

func NewBackupManager(db *bbolt.DB, config *BackupConfig) *BackupManager {
	if config.RetentionDays == nil {
		config.RetentionDays = []int{1, 7, 30}
	}

	return &BackupManager{
		db:            db,
		dataDir:       config.DataDir,
		backupDir:     config.BackupDir,
		retentionDays: config.RetentionDays,
	}
}

func (bm *BackupManager) CreateBackup(ctx context.Context, backupType string) (*BackupInfo, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if err := os.MkdirAll(bm.backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("nexus-%s-%s", backupType, timestamp)

	dbBackupPath := filepath.Join(bm.backupDir, backupName+".db")

	if err := bm.db.View(func(tx *bbolt.Tx) error {
		return tx.CopyFile(dbBackupPath, 0644)
	}); err != nil {
		return nil, fmt.Errorf("failed to backup database: %w", err)
	}

	var totalSize int64
	filepath.Walk(bm.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	dbInfo, _ := os.Stat(dbBackupPath)
	backupSize := int64(0)
	if dbInfo != nil {
		backupSize = dbInfo.Size()
	}
	backupSize += totalSize

	return &BackupInfo{
		Name:      backupName,
		Path:      dbBackupPath,
		Size:      backupSize,
		CreatedAt: time.Now(),
		Type:      backupType,
	}, nil
}

func (bm *BackupManager) ListBackups(ctx context.Context) ([]*BackupInfo, error) {
	entries, err := os.ReadDir(bm.backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []*BackupInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		backupType := "unknown"
		if filepath.Ext(entry.Name()) == ".db" {
			backupType = "database"
		}

		backups = append(backups, &BackupInfo{
			Name:      entry.Name(),
			Path:      filepath.Join(bm.backupDir, entry.Name()),
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
			Type:      backupType,
		})
	}

	return backups, nil
}

func (bm *BackupManager) RestoreBackup(ctx context.Context, backupPath string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	currentDBPath := filepath.Join(bm.dataDir, "metadata.db")
	backupCurrentPath := currentDBPath + ".pre-restore-" + time.Now().Format("20060102-150405")

	if _, err := os.Stat(currentDBPath); err == nil {
		if err := copyFile(currentDBPath, backupCurrentPath); err != nil {
			return fmt.Errorf("failed to backup current database: %w", err)
		}
	}

	if err := copyFile(backupPath, currentDBPath); err != nil {
		return fmt.Errorf("failed to restore database: %w", err)
	}

	return nil
}

func (bm *BackupManager) CleanupOldBackups(ctx context.Context) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	backups, err := bm.ListBackups(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	maxRetention := 0
	for _, days := range bm.retentionDays {
		if days > maxRetention {
			maxRetention = days
		}
	}

	for _, backup := range backups {
		age := int(now.Sub(backup.CreatedAt).Hours() / 24)

		shouldKeep := false
		for _, retention := range bm.retentionDays {
			if age <= retention {
				shouldKeep = true
				break
			}
		}

		if !shouldKeep && age > maxRetention {
			os.Remove(backup.Path)
		}
	}

	return nil
}

func (bm *BackupManager) ScheduleBackups(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bm.CreateBackup(ctx, "scheduled")
			bm.CleanupOldBackups(ctx)
		}
	}
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = dstFile.ReadFrom(srcFile)
	return err
}
