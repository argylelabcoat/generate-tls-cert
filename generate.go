package main

// Copyright 2009 The Go Authors. All rights reserved.

// Use of this source code is governed by a BSD-style

// license that can be found in the LICENSE file.

// +build ignore

// Generate a self-signed X.509 certificate for a TLS server. Outputs to

// 'cert.pem' and 'key.pem' and will overwrite existing files.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	host        = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom   = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011 (default now)")
	validFor    = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	debug       = flag.Bool("debug", false, "Output debug information (.crt) files")
	skipIfValid = flag.Bool("skipIfValid", false, "Check existing leaf certificates and skip generation if they are valid")
	version     = flag.Bool("version", false, "Print the version string")
)

// Version is the version of this tool
const Version = "0.2"

func verifyCert(rootPEM, certPEM string, name string) error {
	certfile, e := ioutil.ReadFile(certPEM)
	if e != nil {
		fmt.Println("cert file failed to load:", e.Error())
		os.Exit(1)
	}

	keyfile, e := ioutil.ReadFile(rootPEM)
	if e != nil {
		fmt.Println("key file failed to load:", e.Error())
		os.Exit(1)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(keyfile)
	if !ok {
		return fmt.Errorf("failed to parse root certificate")
	}

	block, _ := pem.Decode(certfile)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err.Error())
	}

	opts := x509.VerifyOptions{
		DNSName: name,
		Roots:   roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: %v", err.Error())
	}

	return nil
}

func main() {
	flag.Parse()
	if *version {
		fmt.Fprintf(os.Stderr, "generate-tls-cert version %s\n", Version)
		os.Exit(2)
	}
	if len(*host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	if true == *skipIfValid {
		valid := verifyCert("root.pem", "leaf.pem", *host) == nil
		fmt.Printf("Certificate validity reports as: %t\n", valid)
		if true == valid {
			fmt.Println("Skipping Certificate creation.")
			return
		}
	}
	var err error
	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	keyToFile("root.key", rootKey)

	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	if true == *debug {
		debugCertToFile("root.debug.crt", derBytes)
	}

	certToFile("root.pem", derBytes)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	keyToFile("leaf.key", leafKey)

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "test_cert_1",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, h)
		}
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &leafTemplate, &rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	if true == *debug {
		debugCertToFile("leaf.debug.crt", derBytes)
	}
	certToFile("leaf.pem", derBytes)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	keyToFile("client.key", clientKey)

	clientTemplate := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(4),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "client_auth_test_cert",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &clientTemplate, &rootTemplate, &clientKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	if true == *debug {
		debugCertToFile("client.debug.crt", derBytes)
	}

	certToFile("client.pem", derBytes)

	fmt.Fprintf(os.Stdout, `Successfully generated certificates! Here's what you generated.

# Root CA

root.key
	The private key for the root Certificate Authority. Keep this private.

root.pem
	The public key for the root Certificate Authority. Clients should load the
	certificate in this file to connect to the server.

root.debug.crt
	Debug information about the generated certificate.

# Leaf Certificate - Use these to serve TLS traffic.

leaf.key
	Private key (PEM-encoded) for terminating TLS traffic on the server.

leaf.pem
	Public key for terminating TLS traffic on the server.

leaf.debug.crt
	Debug information about the generated certificate

# Client Certificate - You probably don't need these.

client.key: Secret key for TLS client authentication
client.pem: Public key for TLS client authentication

See https://github.com/Shyp/generate-tls-cert for examples of how to use in code.
`)
}

// keyToFile writes a PEM serialization of |key| to a new file called
// |filename|.
func keyToFile(filename string, key *ecdsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
		os.Exit(2)
	}
	if err := pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		panic(err)
	}
}

func certToFile(filename string, derBytes []byte) {
	certOut, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to write data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing cert.pem: %s", err)
	}
}

// debugCertToFile writes a PEM serialization and OpenSSL debugging dump of
// |derBytes| to a new file called |filename|.
func debugCertToFile(filename string, derBytes []byte) {
	cmd := exec.Command("openssl", "x509", "-text", "-inform", "DER")

	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	cmd.Stdout = file
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		panic(err)
	}

	if err := cmd.Start(); err != nil {
		panic(err)
	}
	if _, err := stdin.Write(derBytes); err != nil {
		panic(err)
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		panic(err)
	}
}
