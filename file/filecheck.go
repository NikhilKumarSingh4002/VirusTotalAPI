package main

import (
	"fmt"
	"log"

	vt "github.com/VirusTotal/vt-go"
)

const (
	apiKey   = "API Key"
	filePath = "C:/Program Files/Notepad++/uninstall"
)

func main() {
	// file, err := os.Open(filePath)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer file.Close()

	// hash := sha256.New()
	// if _, err := io.Copy(hash, file); err != nil {
	// 	log.Fatal(err)
	// }
	// sha256sum := hex.EncodeToString(hash.Sum(nil))

	// fmt.Printf("SHA-256 of the file is: %s\n", sha256sum)

	client := vt.NewClient(apiKey)

	fileObj, err := client.GetObject(vt.URL(fmt.Sprintf("files/71B6A493388E7D0B40C83CE903BC6B04")))
	// hash of petya ransomware
	if err != nil {
		log.Fatalf("Failed to get object: %v", err)
	}

	// lastSubmissionDate, err := fileObj.GetInt64("last_submission_date")
	// if err != nil {
	// 	log.Fatal("Could not retrieve last submission date: ", err)
	// }

	// ls := time.Unix(lastSubmissionDate, 0)
	// fmt.Printf("File %s was submitted for the last time on %v\n", fileObj.ID(), ls)

	malicious, err := fileObj.GetInt64("last_analysis_stats.malicious")
	if err != nil {
		log.Printf("Could not retrieve malicious count: %v\n", err)
	} else {
		fmt.Printf("Malicious count: %d\n", malicious)
	}

	meaningful_name, err := fileObj.GetString("meaningful_name")
	if err != nil {
		log.Printf("%v", err)
	} else {
		fmt.Printf("name : %s", meaningful_name)
	}

}
