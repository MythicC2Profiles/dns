package dnsserver

import (
	"encoding/json"
	"github.com/MythicMeta/MythicContainer/logging"
	"log"
	"os"
	"path/filepath"
)

type config struct {
	Instances []instanceConfig `json:"instances"`
}
type instanceConfig struct {
	Port    int      `json:"port"`
	Debug   bool     `json:"debug"`
	BindIP  string   `json:"bind_ip"`
	Domains []string `json:"domains"`
}

var (
	Config = config{}
)

func InitializeLocalConfig() {
	if !fileExists(filepath.Join(getCwdFromExe(), "config.json")) {
		if _, err := os.Create(filepath.Join(getCwdFromExe(), "config.json")); err != nil {
			logging.LogFatalError(err, "[-] config.json doesn't exist and couldn't be created")
		}
	}
	if fileData, err := os.ReadFile("config.json"); err != nil {
		logging.LogError(err, "Failed to read in config.json file")
	} else if err = json.Unmarshal(fileData, &Config); err != nil {
		logging.LogError(err, "Failed to unmarshal config bytes")
	} else {
		logging.LogInfo("[+] Successfully read in config.json")
	}
}

func getCwdFromExe() string {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("[-] Failed to get path to current executable: %v", err)
	}
	return filepath.Dir(exe)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return !info.IsDir()
}
