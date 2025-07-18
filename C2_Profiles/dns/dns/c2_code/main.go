package main

import (
	"github.com/MythicMeta/MythicContainer/logging"
	"mythicDNS/dnsserver"
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
			}
		}()
	}
	forever := make(chan bool)
	<-forever

}
