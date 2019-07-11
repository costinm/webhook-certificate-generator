package main

import (
	"flag"
	"github.com/costinm/webhook-certificate-generator/pkg/istio"
	"github.com/costinm/webhook-certificate-generator/pkg/utils"
	"log"
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

	// Try in cluster first, use KUBECONFIG or default
	client, err := utils.NewClientset(true, "")
	if err != nil {
		log.Fatal("couldn't create clientset: %v", err)
	}

	istio.NewIntermediary(client, &istio.Config{
		TrustDomain: trustDomain,
		Prefix: prefix,
		Watch: true,
		Namespaces:[]string{"default", "istio-system"}})
}
