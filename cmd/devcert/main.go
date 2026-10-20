// devcert generates a self-signed server certificate for local testing only.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	hosts := flag.String("hosts", "localhost,127.0.0.1", "comma-separated DNS names and IP addresses")
	directory := flag.String("out", ".local-tls", "certificate output directory")
	flag.Parse()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "NFC backend local testing"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	for _, host := range strings.Split(*hosts, ",") {
		host = strings.TrimSpace(host)
		if ip := net.ParseIP(host); ip != nil {
			certificate.IPAddresses = append(certificate.IPAddresses, ip)
		} else if host != "" {
			certificate.DNSNames = append(certificate.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &private.PublicKey, private)
	if err != nil {
		log.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		log.Fatal(err)
	}
	if err = os.MkdirAll(*directory, 0700); err != nil {
		log.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{"cert.pem": {Type: "CERTIFICATE", Bytes: der}, "key.pem": {Type: "PRIVATE KEY", Bytes: key}} {
		path := filepath.Join(*directory, name)
		file, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			log.Fatal(e)
		}
		e = pem.Encode(file, block)
		closeErr := file.Close()
		if e != nil {
			log.Fatal(e)
		}
		if closeErr != nil {
			log.Fatal(closeErr)
		}
	}
	fmt.Println("Local self-signed certificate created. This does not install certificate trust.")
}
