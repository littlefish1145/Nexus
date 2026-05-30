package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	address string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "nexusctl",
	Short: "Nexus CLI - Management tool for Nexus storage system",
	Long: `Nexus Control (nexusctl) is a command-line tool for managing
Nexus S3-compatible storage system.`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&address, "address", "http://localhost:8080", "Nexus server address")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func serverRequest(method, path string) (*http.Response, error) {
	req, err := http.NewRequest(method, address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	user := os.Getenv("NEXUS_ADMIN_USER")
	pass := os.Getenv("NEXUS_ADMIN_PASSWORD")
	if user != "" && pass != "" {
		req.SetBasicAuth(user, pass)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cluster status",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := serverRequest("GET", "/health")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error connecting to server: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
			os.Exit(1)
		}

		var health map[string]interface{}
		if err := json.Unmarshal(body, &health); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Status:    %v\n", health["status"])
		fmt.Printf("Timestamp: %v\n", health["timestamp"])

		if checks, ok := health["checks"].(map[string]interface{}); ok {
			fmt.Println("\nChecks:")
			for k, v := range checks {
				fmt.Printf("  %-15s %v\n", k+":", v)
			}
		}
	},
}

var tieringCmd = &cobra.Command{
	Use:   "tiering",
	Short: "Tiering management commands",
}

var tieringRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run tiering decision and execute migrations",
	Run: func(cmd *cobra.Command, args []string) {
		bucket, _ := cmd.Flags().GetString("bucket")

		path := "/admin/tiering/run"
		if bucket != "" {
			path = path + "?bucket=" + bucket
		}

		resp, err := serverRequest("POST", path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "Error: %s (status %d)\n", string(body), resp.StatusCode)
			os.Exit(1)
		}

		fmt.Println("Tiering execution triggered successfully")
	},
}

var tieringStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show tiering status",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := serverRequest("GET", "/admin/tiering/status")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(body))
	},
}

var vectorCmd = &cobra.Command{
	Use:   "vector",
	Short: "Vector index management commands",
}

var vectorRebuildCmd = &cobra.Command{
	Use:   "rebuild",
	Short: "Rebuild vector index",
	Run: func(cmd *cobra.Command, args []string) {
		bucket, _ := cmd.Flags().GetString("bucket")

		path := "/admin/vector/rebuild"
		if bucket != "" {
			path = path + "?bucket=" + bucket
		}

		resp, err := serverRequest("POST", path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "Error: %s (status %d)\n", string(body), resp.StatusCode)
			os.Exit(1)
		}

		fmt.Println("Vector index rebuild triggered successfully")
	},
}

var vectorStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show vector index statistics",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := serverRequest("GET", "/admin/vector/stats")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(body))
	},
}

var cryptoCmd = &cobra.Command{
	Use:   "crypto",
	Short: "Cryptographic operations",
}

var cryptoRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate encryption keys",
	Run: func(cmd *cobra.Command, args []string) {
		bucket, _ := cmd.Flags().GetString("bucket")

		path := "/admin/crypto/rotate"
		if bucket != "" {
			path = path + "?bucket=" + bucket
		}

		resp, err := serverRequest("POST", path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "Error: %s (status %d)\n", string(body), resp.StatusCode)
			os.Exit(1)
		}

		fmt.Println("Key rotation triggered successfully")
	},
}

var cryptoStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show encryption status",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := serverRequest("GET", "/admin/crypto/status")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(body))
	},
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Performance profiling",
	Run: func(cmd *cobra.Command, args []string) {
		cpuduration, _ := cmd.Flags().GetString("cpu")

		path := "/debug/pprof/profile"
		if cpuduration != "" {
			path = path + "?seconds=" + cpuduration
		}

		resp, err := serverRequest("GET", path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "Error: %s (status %d)\n", string(body), resp.StatusCode)
			os.Exit(1)
		}

		outFile, _ := cmd.Flags().GetString("output")
		if outFile == "" {
			outFile = "profile.out"
		}

		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		if _, err := io.Copy(f, resp.Body); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing profile: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Profile saved to %s\n", outFile)
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)

	rootCmd.AddCommand(tieringCmd)
	tieringCmd.AddCommand(tieringRunCmd)
	tieringRunCmd.Flags().String("bucket", "", "Specific bucket to run tiering on")
	tieringCmd.AddCommand(tieringStatusCmd)

	rootCmd.AddCommand(vectorCmd)
	vectorCmd.AddCommand(vectorRebuildCmd)
	vectorRebuildCmd.Flags().String("bucket", "", "Specific bucket to rebuild index for")
	vectorCmd.AddCommand(vectorStatsCmd)

	rootCmd.AddCommand(cryptoCmd)
	cryptoCmd.AddCommand(cryptoRotateCmd)
	cryptoRotateCmd.Flags().String("bucket", "", "Specific bucket to rotate keys for")
	cryptoCmd.AddCommand(cryptoStatusCmd)

	rootCmd.AddCommand(profileCmd)
	profileCmd.Flags().String("cpu", "30", "CPU profile duration in seconds")
	profileCmd.Flags().String("output", "", "Output file path (default: profile.out)")

	rootCmd.AddCommand(userCmd)
}
