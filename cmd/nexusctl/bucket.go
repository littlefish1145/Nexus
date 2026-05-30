// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var bucketCmd = &cobra.Command{
	Use:   "bucket",
	Short: "Bucket management commands",
}

var bucketCreateCmd = &cobra.Command{
	Use:   "create <bucket-name>",
	Short: "Create a new bucket",
	Args:  cobra.ExactArgs(1),
	RunE:  runBucketCreate,
}

var bucketListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all buckets",
	RunE:  runBucketList,
}

var bucketDeleteCmd = &cobra.Command{
	Use:   "delete <bucket-name>",
	Short: "Delete a bucket",
	Args:  cobra.ExactArgs(1),
	RunE:  runBucketDelete,
}

var bucketInfoCmd = &cobra.Command{
	Use:   "info <bucket-name>",
	Short: "Get bucket information",
	Args:  cobra.ExactArgs(1),
	RunE:  runBucketInfo,
}

var bucketObjectsCmd = &cobra.Command{
	Use:   "objects <bucket-name>",
	Short: "List objects in a bucket",
	Args:  cobra.ExactArgs(1),
	RunE:  runBucketObjects,
}

var bucketSetACLCmd = &cobra.Command{
	Use:   "set-acl <bucket-name>",
	Short: "Set bucket ACL (private, public-read, public-read-write, authenticated-read)",
	Args:  cobra.ExactArgs(1),
	RunE:  runBucketSetACL,
}

var bucketGetACLCmd = &cobra.Command{
	Use:   "get-acl <bucket-name>",
	Short: "Get bucket ACL",
	Args:  cobra.ExactArgs(1),
	RunE:  runBucketGetACL,
}

var bucketACL = struct {
	AccessKey string
	SecretKey string
}{
	AccessKey: "",
	SecretKey: "",
}

type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Buckets struct {
		Bucket []Bucket `xml:"Bucket"`
	} `xml:"Buckets"`
}

type Bucket struct {
	Name         string    `xml:"Name"`
	CreationDate time.Time `xml:"CreationDate"`
}

type ListBucketResult struct {
	XMLName   xml.Name    `xml:"ListBucketResult"`
	Name      string      `xml:"Name"`
	Prefix    string      `xml:"Prefix"`
	Marker    string      `xml:"Marker"`
	MaxKeys   int         `xml:"MaxKeys"`
	IsTruncated bool      `xml:"IsTruncated"`
	Contents  []Object `xml:"Contents"`
}

type Object struct {
	Key          string    `xml:"Key"`
	LastModified time.Time `xml:"LastModified"`
	ETag        string    `xml:"ETag"`
	Size        int64     `xml:"Size"`
}

func init() {
	rootCmd.AddCommand(bucketCmd)
	bucketCmd.AddCommand(bucketCreateCmd)
	bucketCmd.AddCommand(bucketListCmd)
	bucketCmd.AddCommand(bucketDeleteCmd)
	bucketCmd.AddCommand(bucketInfoCmd)
	bucketCmd.AddCommand(bucketObjectsCmd)
	bucketCmd.AddCommand(bucketSetACLCmd)
	bucketCmd.AddCommand(bucketGetACLCmd)

	bucketCreateCmd.Flags().StringVar(&bucketACL.AccessKey, "access-key", "", "Access key (env: NEXUS_ACCESS_KEY)")
	bucketCreateCmd.Flags().StringVar(&bucketACL.SecretKey, "secret-key", "", "Secret key (env: NEXUS_SECRET_KEY)")

	bucketCreateCmd.Flags().String("acl", "private", "Bucket ACL (private, public-read, public-read-write)")
	bucketSetACLCmd.Flags().String("acl", "private", "Bucket ACL (private, public-read, public-read-write, authenticated-read)")
}

func getAuthHeader() string {
	ak := bucketACL.AccessKey
	sk := bucketACL.SecretKey

	if ak == "" {
		ak = os.Getenv("NEXUS_ACCESS_KEY")
	}
	if sk == "" {
		sk = os.Getenv("NEXUS_SECRET_KEY")
	}

	creds := fmt.Sprintf("%s:%s", ak, sk)
	return "Basic " + base64Encode(creds)
}

func base64Encode(s string) string {
	return strings.TrimRight(fmt.Sprintf("%s", encodeBase64([]byte(s))), "=")
}

func encodeBase64(src []byte) string {
	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	const paddingChar = '='

	if len(src) == 0 {
		return ""
	}

	dst := make([]byte, (len(src)+2)/3*4)
	for i, j := 0, 0; i < len(src); i, j = i+3, j+4 {
		var val uint32
		switch len(src) - i {
		case 1:
			val = uint32(src[i]) << 16
			dst[j] = encodeStd[val>>18&0x3F]
			dst[j+1] = encodeStd[val>>12&0x3F]
			dst[j+2] = paddingChar
			dst[j+3] = paddingChar
		case 2:
			val = uint32(src[i])<<16 | uint32(src[i+1])<<8
			dst[j] = encodeStd[val>>18&0x3F]
			dst[j+1] = encodeStd[val>>12&0x3F]
			dst[j+2] = encodeStd[val>>6&0x3F]
			dst[j+3] = paddingChar
		default:
			val = uint32(src[i])<<16 | uint32(src[i+1])<<8 | uint32(src[i+2])
			dst[j] = encodeStd[val>>18&0x3F]
			dst[j+1] = encodeStd[val>>12&0x3F]
			dst[j+2] = encodeStd[val>>6&0x3F]
			dst[j+3] = encodeStd[val&0x3F]
		}
	}
	return string(dst)
}

func runBucketCreate(cmd *cobra.Command, args []string) error {
	bucketName := args[0]
	url := fmt.Sprintf("%s/%s", address, bucketName)

	acl, _ := cmd.Flags().GetString("acl")

	req, err := http.NewRequestWithContext(context.Background(), "PUT", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", getAuthHeader())
	if acl != "" {
		req.Header.Set("x-amz-acl", acl)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create bucket: %s (status %d)", string(body), resp.StatusCode)
	}

	fmt.Printf("✓ Bucket '%s' created successfully (ACL: %s)\n", bucketName, acl)
	return nil
}

func runBucketList(cmd *cobra.Command, args []string) error {
	req, err := http.NewRequestWithContext(context.Background(), "GET", address, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", getAuthHeader())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to list buckets: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to list buckets: %s (status %d)", string(body), resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var result ListAllMyBucketsResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Buckets.Bucket) == 0 {
		fmt.Println("No buckets found")
		return nil
	}

	fmt.Printf("%-30s %s\n", "BUCKET NAME", "CREATION DATE")
	fmt.Println(strings.Repeat("-", 55))
	for _, bucket := range result.Buckets.Bucket {
		fmt.Printf("%-30s %s\n", bucket.Name, bucket.CreationDate.Format("2006-01-02 15:04:05"))
	}
	return nil
}

func runBucketDelete(cmd *cobra.Command, args []string) error {
	bucketName := args[0]
	url := fmt.Sprintf("%s/%s", address, bucketName)

	req, err := http.NewRequestWithContext(context.Background(), "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", getAuthHeader())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete bucket: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete bucket: %s (status %d)", string(body), resp.StatusCode)
	}

	fmt.Printf("✓ Bucket '%s' deleted successfully\n", bucketName)
	return nil
}

func runBucketInfo(cmd *cobra.Command, args []string) error {
	bucketName := args[0]

	objects, err := listObjects(bucketName)
	if err != nil {
		fmt.Printf("⚠ Warning: %v\n", err)
	}

	var totalSize int64
	var objectCount int
	for _, obj := range objects {
		totalSize += obj.Size
		objectCount++
	}

	fmt.Printf("%-20s %s\n", "Bucket Name:", bucketName)
	fmt.Printf("%-20s %d\n", "Objects:", objectCount)
	fmt.Printf("%-20s %s\n", "Total Size:", formatBytes(totalSize))

	return nil
}

func runBucketObjects(cmd *cobra.Command, args []string) error {
	bucketName := args[0]
	prefix, _ := cmd.Flags().GetString("prefix")

	objects, err := listObjectsWithPrefix(bucketName, prefix)
	if err != nil {
		return err
	}

	if len(objects) == 0 {
		fmt.Println("No objects found")
		return nil
	}

	fmt.Printf("%-40s %12s %s\n", "OBJECT NAME", "SIZE", "LAST MODIFIED")
	fmt.Println(strings.Repeat("-", 75))
	for _, obj := range objects {
		modified := obj.LastModified.Format("2006-01-02 15:04:05")
		fmt.Printf("%-40s %12s %s\n", truncateString(obj.Key, 40), formatBytes(obj.Size), modified)
	}
	fmt.Printf("\n%d objects, %s total\n", len(objects), formatBytes(sumSizes(objects)))
	return nil
}

func listObjects(bucketName string) ([]Object, error) {
	return listObjectsWithPrefix(bucketName, "")
}

func listObjectsWithPrefix(bucketName, prefix string) ([]Object, error) {
	url := fmt.Sprintf("%s/%s?listType=2", address, bucketName)
	if prefix != "" {
		url += "&prefix=" + prefix
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", getAuthHeader())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list objects: %s (status %d)", string(body), resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result ListBucketResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Contents, nil
}

func sumSizes(objects []Object) int64 {
	var total int64
	for _, obj := range objects {
		total += obj.Size
	}
	return total
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func runBucketSetACL(cmd *cobra.Command, args []string) error {
	bucketName := args[0]
	acl, _ := cmd.Flags().GetString("acl")

	validACLs := map[string]bool{
		"private":            true,
		"public-read":        true,
		"public-read-write":  true,
		"authenticated-read": true,
	}
	if !validACLs[acl] {
		return fmt.Errorf("invalid ACL '%s'. Valid values: private, public-read, public-read-write, authenticated-read", acl)
	}

	url := fmt.Sprintf("%s/%s?acl", address, bucketName)

	req, err := http.NewRequestWithContext(context.Background(), "PUT", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", getAuthHeader())
	req.Header.Set("x-amz-acl", acl)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to set bucket ACL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to set bucket ACL: %s (status %d)", string(body), resp.StatusCode)
	}

	fmt.Printf("✓ Bucket '%s' ACL set to '%s'\n", bucketName, acl)
	return nil
}

func runBucketGetACL(cmd *cobra.Command, args []string) error {
	bucketName := args[0]

	url := fmt.Sprintf("%s/%s?acl", address, bucketName)

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", getAuthHeader())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get bucket ACL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get bucket ACL: %s (status %d)", string(body), resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	fmt.Println(string(body))
	return nil
}
