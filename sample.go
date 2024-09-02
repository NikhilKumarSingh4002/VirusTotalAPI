package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	vt "github.com/VirusTotal/vt-go"
)

const (
	apiKey     = "API Key"
	folderPath = "C:/Users/Nikhil.Singh/Downloads"
)

// computeFileHash calculates the SHA-256 hash of the given file.
func computeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("error opening file %s: %w", filePath, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("error hashing file %s: %w", filePath, err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// getMaliciousCount queries VirusTotal for the malicious count of a file given its SHA-256 hash.
func getMaliciousCount(sha256sum string, client *vt.Client) (int, error) {
	fileObj, err := client.GetObject(vt.URL(fmt.Sprintf("files/%s", sha256sum)))
	if err != nil {
		return 0, fmt.Errorf("error querying VirusTotal for hash %s: %w", sha256sum, err)
	}

	malicious, err := fileObj.GetInt64("last_analysis_stats.malicious")
	if err != nil {
		return 0, fmt.Errorf("could not retrieve malicious count for hash %s: %w", sha256sum, err)
	}

	return int(malicious), nil
}

func getBehaviour(sha256sum string) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s/behaviour_summary", sha256sum)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		return
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error performing request: %v\n", err)
		return
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("Error reading response body: %v\n", err)
		return
	}

	fmt.Println("Sandbox Behaviour:")
	fmt.Println(string(body))
}

func main() {
	fileHashes := make(map[string]int)
	client := vt.NewClient(apiKey)

	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		sha256sum, err := computeFileHash(path)
		if err != nil {
			log.Printf("%v\n", err)
			return nil
		}

		maliciousCount, err := getMaliciousCount(sha256sum, client)
		if err != nil {
			log.Printf("%v\n", err)
			return nil
		}

		getBehaviour(sha256sum)

		fileHashes[sha256sum] = maliciousCount
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking the path %s: %v\n", folderPath, err)
	}

	for key, value := range fileHashes {
		fmt.Printf("File hash key: %s\n", key)
		fmt.Printf("Malicious count: %d\n", value)
	}
}
