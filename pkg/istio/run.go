package istio

import (
	"fmt"
	"github.com/costinm/webhook-certificate-generator/pkg/certgenerator"
	"io/ioutil"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"

	"strings"
	"time"

	"github.com/costinm/webhook-certificate-generator/pkg/utils"
	"k8s.io/client-go/kubernetes"
)

// BUG: k8s removes the URL entries from the CSR ! Can't be used for istio, only for the DNS-based certs
// ( pilot, citadel, webhooks ). This seems due to cloudfare/cfssl lacking support for URL-based, they copy
// the fields they know.


// Changes from 'certgenerator' package:
// - autoapprove is on by default
// - no option to patch webhooks
// - watch SA and create istio-style certs
//
//
// Generated certificate:
// - will have Spiffe URL SAN
// - will have DNS entries for serviceaccount.namespace and serviceaccount.namespace.svc, so it can be used
// in webhooks or by non-istio clients. If service account ends with "-service-account" (common in istio), the
// suffis is removed from the service name. This works well if the name of SA and service is matching.
//
// Todo: optionally add K8S-compatible CN=sa,O=group.. - verify it works for k8s auth with mtls.
// This is normally used for users.
// Service accounts authenticate with system:serviceaccount:NAMESPACE:SA, and have groups
// system:serviceaccounts and system:serviceaccounts:NAMESPACE
//
// CSR generation: openssl req -new -key key.pem -out csr.pem -sub "/cn=foo/o=bar/o=bar2"


// Config holds required parameters
type Config struct {
	TrustDomain string

	// Watch will block watching for new service account actions.
	Watch bool

	// Prefix to use for the cert. Empty to set Istio standard cert name
	Prefix string

	// Namespaces to watch, empty for all
	Namespaces   []string

	ServiceName string // Service name to generate certificate for
	SecretName  string // Secret name to store generated cert in

	nsMap map[string]bool
}

// TODO: add k8s public key
// TODO: delete secrets when SA deleted
// TODO: don't modify if recently updated (and has our secret )
//

// Remote handles a remote cluster, managing its secrets.
// Uses a pilot-style certificate, with a kube-config
func Remote(primary *kubernetes.Clientset, secret v1.Secret) error {
	return nil
}

// Primary cluster updates.
// Will connect to a cluster and update its secrets.
func Run(cfg *Config) error {
	if len(cfg.Namespaces) > 0 {
		cfg.nsMap = make(map[string]bool)
		for _, k := range cfg.Namespaces {
			cfg.nsMap[k] = true
		}
	}

	// Try in cluster first, use KUBECONFIG or default
	client, err := utils.NewClientset(true, "")
	if err != nil {
		return fmt.Errorf("couldn't create clientset: %v", err)
	}

	if cfg.Watch {
		wat, err := client.CoreV1().ServiceAccounts("").Watch(metav1.ListOptions{})
		if err != nil {
			return err
		}
		for ev := range wat.ResultChan() {
			// TODO: added/deleted
			sa, _ := ev.Object.(*v1.ServiceAccount)
			err = GenerateSACert(cfg, sa.Namespace, sa.Name, client)
			if err != nil {
				return err
			}
		}
	} else {
		sal, err := client.CoreV1().ServiceAccounts("").List(metav1.ListOptions{})
		if err != nil {
			return err
		}

		for _, sa := range sal.Items {
			err = GenerateSACert(cfg, sa.Namespace, sa.Name, client)
			if err != nil {
				return err
			}

		}
	}

	return nil
}

func NewIntermediary(client *kubernetes.Clientset, cfg *Config) error {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intermediary2",
			Namespace: "istio-system",
		},
		Data: make(map[string][]byte),
	}

	csrName, err := certgenerator.CreateCerificateSigningRequest(client, secret, "istio-system", "intermediary-ca2",
		"", true)
	if err != nil {
		return fmt.Errorf("couldn't create certificate signing request: %v", err)
	}
	_, err = utils.ApproveCSR(client, csrName)
	if err != nil {
		return fmt.Errorf("couldn't approve CSR: %v", err)
	}

	err = certgenerator.WaitForCertificate(client, csrName)
	if err != nil {
		return fmt.Errorf("error waiting for GenerateSACert: %v", err)
	}

	certificate, err := utils.GetCertificate(client, csrName)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %v", err)
	}
	// Update secret
	secret.Data[cfg.Prefix + "cert-chain.pem"] = certificate

	for name, valBytes := range secret.Data {
		//valBytes, err := base64.URLEncoding.DecodeString(string(val))
		//if err != nil {
		//	log.Fatalln("Can't decode ", err, string(val))
		//}

		ioutil.WriteFile(name, valBytes,0700)
		log.Println("Wrote: " + name)

	}
	return nil
}

// Note: this will reuse the existing key.pem, if the secret already exists !
// Will add the k8s-signed certificate
// Test shows about 82ms for first step, 400 ms for 2/3, and 300 ms for 4th step - or about 1 sec per cert.
// However first few were fast - so it might be throttling.
// TODO: evaluate if they can be in parallel.
func GenerateSACert(cfg *Config, namespace string, sa string, client *kubernetes.Clientset) error {
	if cfg.nsMap != nil && !cfg.nsMap[namespace] {
		return nil
	}

	secretName := "istio." + sa

	serviceName := sa
	// Common pattern (in istio)
	if strings.HasSuffix(sa, "-service-account") {
		serviceName = sa[0: len(sa) - len("-service-account")]
	}

	// Fetch the secret from Kubernetes.
	secret, err := utils.GetSecret(client, namespace, secretName)
	if err != nil {
		return fmt.Errorf("failed to fetch secret: %v", err)
	}

	secret.Type = "istio.io/key-and-cert"

	t0 := time.Now()

	// Create Kubernetes CSR
	csrName, err := certgenerator.CreateCerificateSigningRequest(client, secret, namespace, serviceName, "", false)
	if err != nil {
		return fmt.Errorf("couldn't create certificate signing request: %v", err)
	}

	t1 := time.Now()

	_, err = utils.ApproveCSR(client, csrName)
	if err != nil {
		return fmt.Errorf("couldn't approve CSR: %v", err)
	}
	t2 := time.Now()

	err = certgenerator.WaitForCertificate(client, csrName)
	if err != nil {
		return fmt.Errorf("error waiting for GenerateSACert: %v", err)
	}

	certificate, err := utils.GetCertificate(client, csrName)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %v", err)
	}
	t3 := time.Now()

	// Update secret
	secret.Data[cfg.Prefix + "cert-chain.pem"] = certificate

	// TODO: Add k8s CA if missing
	// /var/run/secrets/kubernetes.io/serviceaccount/ca.crt if in cluster
	// Appears to be the secret in the config.

	_, err = utils.CreateSecret(client, secret)
	if err != nil {
		return fmt.Errorf("couldn't create secret: %v", err)
	}
	t4 := time.Now()

	log.Println("Created secret ", secret.Namespace, secret.Name, t4.Sub(t3), t3.Sub(t2), t2.Sub(t1), t1.Sub(t0))

	return nil
}

