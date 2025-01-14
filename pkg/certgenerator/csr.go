package certgenerator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/joelspeed/webhook-certificate-generator/pkg/utils"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// createCerificateSigningRequest creates a Kubernetes CSR for the given service
func CreateCerificateSigningRequest(client *kubernetes.Clientset, secret *v1.Secret, namespace string, serviceName string, secretName string, isCA bool) (string, error) {
	csrPem, err := createCSRPem(secret, namespace, serviceName, isCA)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR Pem: %v", err)
	}
	log.Print("CSR:\n", string(csrPem))

	csr := &certsv1beta1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.%s", serviceName, namespace),
		},
		Spec: certsv1beta1.CertificateSigningRequestSpec{
			Request: csrPem,
			Usages: []certsv1beta1.KeyUsage{
				certsv1beta1.UsageDigitalSignature,
				certsv1beta1.UsageKeyEncipherment,
				certsv1beta1.UsageServerAuth,
			},
		},
	}
	_, err = utils.CreateCSR(client, csr)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %v", err)
	}
	return csr.Name, nil
}

func createCSRPem(secret *v1.Secret, namespace string, serviceName string, isCA bool) ([]byte, error) {
	privateKey, err := getPrivateKey(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %v", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s.%s.svc", serviceName, namespace),
		},
		DNSNames: []string{
			serviceName,
			fmt.Sprintf("%s.%s", serviceName, namespace),
			fmt.Sprintf("%s.%s.svc", serviceName, namespace),
		},
	}

	caExt, err := createCAExtension(isCA)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA Extension")
	}

	template.ExtraExtensions = []pkix.Extension{caExt}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

func getPrivateKey(secret *v1.Secret) (*rsa.PrivateKey, error) {
	// Load the existing key from the secret
	if keyPem, ok := secret.Data["key.pem"]; ok {
		if len(keyPem) > 0 {
			pemBlock, _ := pem.Decode(keyPem)
			if pemBlock == nil {
				return nil, fmt.Errorf("failed to decode private key pem")
			}
			return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		}
	}

	// Generate a new key and put it into the secret
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("couldn't create private key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(newKey),
	}

	secret.Data["key.pem"] = pem.EncodeToMemory(pemBlock)

	return newKey, nil

}

// BasicConstraints CSR information RFC 5280, 4.2.1.9
type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func createCAExtension(isCA bool) (pkix.Extension, error) {
	val, err := asn1.Marshal(BasicConstraints{isCA, 0})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal basic constraints: %v", err)
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Value:    val,
		Critical: true,
	}, nil
}
