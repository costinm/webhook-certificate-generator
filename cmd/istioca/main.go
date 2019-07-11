package main

import (
	"flag"
	"github.com/costinm/webhook-certificate-generator/pkg/istio"
	"os"
)


// Will read all Service accounts and for each will generate a istio-compatible secret.
// TODO: option to run as a deamon, watching for new service accounts.
// TODO: option to ignore present files
func main() {
	// required for glog
	flag.CommandLine.Parse(append(os.Args[1:], "--logtostderr"))

	trustDomain := os.Getenv("TRUST_DOMAIN")
	if trustDomain == "" {
		trustDomain = "cluster.local"
	}
	//prefix := os.Getenv("CHAIN_PREFIX")
	prefix := "k8s."

	istio.Run(&istio.Config{
		TrustDomain: trustDomain,
		Prefix: prefix,
		Watch: true,
		Namespaces:[]string{"default", "istio-system"}})
}
