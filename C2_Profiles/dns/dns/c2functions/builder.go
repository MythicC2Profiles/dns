package c2functions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
	"github.com/MythicMeta/MythicContainer/logging"
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

func getC2JsonConfig() (*config, error) {
	currentConfig := config{}
	configBytes, err := os.ReadFile(filepath.Join(".", "dns", "c2_code", "config.json"))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(configBytes, &currentConfig)
	if err != nil {
		logging.LogError(err, "Failed to unmarshal config bytes")
		return nil, err
	}
	return &currentConfig, nil
}
func writeC2JsonConfig(cfg *config) error {
	jsonBytes, err := json.MarshalIndent(*cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(".", "dns", "c2_code", "config.json"), jsonBytes, 644)
}

var version = "0.0.8"
var dnsc2definition = c2structs.C2Profile{
	Name:             "dns",
	Author:           "@its_a_feature_",
	Description:      fmt.Sprintf("Uses DNS A, AAAA, and TXT queries for connectivity\nCURRENTLY IN BETA! USE WITH CAUTION!"),
	IsP2p:            false,
	IsServerRouted:   true,
	SemVer:           version,
	ServerBinaryPath: filepath.Join(".", "dns", "c2_code", "mythic_dns_server"),
	ConfigCheckFunction: func(message c2structs.C2ConfigCheckMessage) c2structs.C2ConfigCheckMessageResponse {
		response := c2structs.C2ConfigCheckMessageResponse{
			Success: true,
			Message: fmt.Sprintf("Called config check\n%v", message),
		}
		currentConfig, err := getC2JsonConfig()
		if err != nil {
			response.Success = false
			response.Message = err.Error()
			return response
		}
		domains, err := message.GetArrayArg("domains")
		if err != nil {
			response.Success = false
			response.Message = err.Error()
			return response
		}
		ports := []int{}
		for i, _ := range currentConfig.Instances {
			ports = append(ports, currentConfig.Instances[i].Port)
			for _, domain := range domains {
				if !slices.Contains(currentConfig.Instances[i].Domains, domain) {
					currentConfig.Instances[i].Domains = append(currentConfig.Instances[i].Domains, domain)
				}
			}
		}
		err = writeC2JsonConfig(currentConfig)
		if err != nil {
			response.Success = false
			response.Message = err.Error()
			return response
		}
		response.Success = true
		response.Message = fmt.Sprintf("All domains are included and ready!\nBe sure to connect or redirect via one of the following ports:\n%v\n", ports)
		response.RestartInternalServer = true
		return response
	},
	GetRedirectorRulesFunction: func(message c2structs.C2GetRedirectorRuleMessage) c2structs.C2GetRedirectorRuleMessageResponse {
		response := c2structs.C2GetRedirectorRuleMessageResponse{
			Success: false,
			Message: "Function not supported yet",
		}
		return response
	},
	OPSECCheckFunction: func(message c2structs.C2OPSECMessage) c2structs.C2OPSECMessageResponse {
		response := c2structs.C2OPSECMessageResponse{
			Success: true,
			Message: fmt.Sprintf("Called opsec check:\n%v", message),
		}
		return response
	},
	GetIOCFunction: func(message c2structs.C2GetIOCMessage) c2structs.C2GetIOCMessageResponse {
		response := c2structs.C2GetIOCMessageResponse{Success: true}
		domains, err := message.GetArrayArg("domains")
		if err != nil {
			response.Success = false
			return response
		}
		for _, domain := range domains {
			response.IOCs = append(response.IOCs, c2structs.IOC{
				Type: "Domain",
				IOC:  domain,
			})
		}
		return response
	},
	SampleMessageFunction: func(message c2structs.C2SampleMessageMessage) c2structs.C2SampleMessageResponse {
		response := c2structs.C2SampleMessageResponse{Success: true, Message: "Function not supported yet"}

		return response
	},
	HostFileFunction: func(message c2structs.C2HostFileMessage) c2structs.C2HostFileMessageResponse {
		return c2structs.C2HostFileMessageResponse{
			Success:               false,
			RestartInternalServer: false,
			Error:                 "Function not supported yet",
		}
	},
}
var dnsc2parameters = []c2structs.C2Parameter{
	{
		Name:          "domains",
		Description:   "Series of domains to use",
		DefaultValue:  []string{"domain.com"},
		ParameterType: c2structs.C2_PARAMETER_TYPE_ARRAY,
		Required:      true,
	},
	{
		Name:          "killdate",
		Description:   "Kill Date",
		DefaultValue:  365,
		ParameterType: c2structs.C2_PARAMETER_TYPE_DATE,
		Required:      false,
	},
	{
		Name:          "encrypted_exchange_check",
		Description:   "Perform Key Exchange",
		DefaultValue:  true,
		ParameterType: c2structs.C2_PARAMETER_TYPE_BOOLEAN,
		Required:      false,
	},
	{
		Name:          "callback_jitter",
		Description:   "Callback Jitter in percent",
		DefaultValue:  23,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "AESPSK",
		Description:   "Encryption Type",
		DefaultValue:  "aes256_hmac",
		ParameterType: c2structs.C2_PARAMETER_TYPE_CHOOSE_ONE,
		Required:      false,
		IsCryptoType:  true,
		Choices: []string{
			"aes256_hmac",
			"none",
		},
	},
	{
		Name:          "callback_interval",
		Description:   "Callback Interval in seconds",
		DefaultValue:  10,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "domain_rotation",
		Description:   "Domain rotation pattern. Fail-over uses each one in order until it can't communicate with it successfully and moves on. Round-robin makes each request to the next host in the list.",
		ParameterType: c2structs.C2_PARAMETER_TYPE_CHOOSE_ONE,
		Choices: []string{
			"round-robin",
			"random",
			"fail-over",
		},
	},
	{
		Name:          "failover_threshold",
		Description:   "Domain fail-over threshold for how many times to keep trying one host before moving onto the next",
		DefaultValue:  5,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
	},
	{
		Name:          "dns_server",
		Description:   "IP:Port of DNS server to use",
		DefaultValue:  "8.8.8.8:53",
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
	},
	{
		Name:         "record_type",
		Description:  "What type of DNS responses to use - A, AAAA, or TXT",
		DefaultValue: "A",
		Choices: []string{
			"A", "AAAA", "TXT",
		},
		ParameterType: c2structs.C2_PARAMETER_TYPE_CHOOSE_ONE,
	},
	{
		Name:          "max_query_length",
		Description:   "Maximum DNS Query length (must be <= 255 per DNS)",
		DefaultValue:  255,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
	},
	{
		Name:          "max_subdomain_length",
		Description:   "Maximum DNS SubDomain length (must be <= 64 per DNS)",
		DefaultValue:  64,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
	},
}

func Initialize() {
	c2structs.AllC2Data.Get("dns").AddC2Definition(dnsc2definition)
	c2structs.AllC2Data.Get("dns").AddParameters(dnsc2parameters)
}
