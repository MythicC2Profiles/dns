package main

import (
	"mythicDNS/dnsserver"
	"os"

	"github.com/MythicMeta/MythicContainer/logging"
)

func main() {
	dnsserver.InitializeLocalConfig()
	for _, instance := range dnsserver.Config.Instances {
		logging.LogInfo("Initializing dns", "instance", instance)
		server := dnsserver.Initialize(instance)
		// start serving up API routes
		logging.LogInfo("Starting dns server", "instance", instance)
		go func() {
			err := server.ListenAndServe()
			if err != nil {
				logging.LogError(err, "stopped listening", "server", instance)
				os.Exit(1)
			}
		}()
	}
	forever := make(chan bool)
	<-forever

}
