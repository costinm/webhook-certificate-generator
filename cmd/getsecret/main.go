package main

import (
	"flag"
	"github.com/costinm/webhook-certificate-generator/pkg/utils"
	"io/ioutil"
	"log"
)

var (
	ns = flag.String("n", "default", "namespace")
	secretName = flag.String("name", "istio.default", "secret name")
)

// Will read a secret, save each file inside in the current directory
//
func main() {
	// required for glog
	flag.Parse()

	// Try in cluster first, use KUBECONFIG or default
	client, err := utils.NewClientset(true, "")
	if err != nil {
		log.Fatal("couldn't create clientset:", err)
	}

	secret, err := utils.GetSecret(client, *ns, *secretName)
	if err != nil {
		log.Fatal("Can't get secret ", err)
	}

	for name, valBytes := range secret.Data {
		//valBytes, err := base64.URLEncoding.DecodeString(string(val))
		//if err != nil {
		//	log.Fatalln("Can't decode ", err, string(val))
		//}

		ioutil.WriteFile(name, valBytes,0700)
		log.Println("Wrote: " + name)

	}

	log.Println("Done")
}
