package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/helmfile/vals"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var log *logrus.Logger

type Cert struct {
	Name     string `yaml:"Name"`
	CertPath string `yaml:"Cert"`
	KeyPath  string `yaml:"Key"`
	CaPath   string `yaml:"CA"`
}

type Config struct {
	KeystorePath string `yaml:"KeystorePath"`
	KeystorePass string `yaml:"KeystorePassword"`
	Certs        []Cert `yaml:"Certs"`
	OnUpdate     string `yaml:"OnUpdate,omitempty"`
}

func readConfigFile(configFile string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	configYaml, err := os.ReadFile(configFile)
	if err != nil {
		return result, err
	}

	err = yaml.Unmarshal(configYaml, &result)
	if err != nil {
		return result, err
	}
	return result, err
}

/*
KeystorePath: /tmp/keystore.jks
KeystorePassword: changeit
OnUpdate: |-

	echo "Keystore updated"
	systemctl restart my-service

Certs:
  - Name: key1
    Cert: tests/wildcard.crt
    Key: tests/wildcard.key
    CA: tests/ca.crt
*/
func getFromVals(cfg map[string]interface{}) (Config, error) {
	var renderedConfig Config
	runtime, err := vals.New(vals.Options{
		CacheSize: 300,
	})
	if err != nil {
		return renderedConfig, err
	}

	// Render the configuration using vals
	valsRendered, err := runtime.Eval(cfg)
	if err != nil {
		return renderedConfig, err
	}

	// Marshal the rendered values back into YAML format
	renderedYaml, err := yaml.Marshal(valsRendered)
	if err != nil {
		return renderedConfig, err
	}

	// Unmarshal the YAML back into the Config struct
	err = yaml.Unmarshal(renderedYaml, &renderedConfig)
	if err != nil {
		return renderedConfig, err
	}

	return renderedConfig, nil
}

func readKeyStore(filename string, password []byte) (keystore.KeyStore, error) {
	var ks keystore.KeyStore
	f, err := os.Open(filename)
	if err != nil {
		return ks, err
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	ks = keystore.New()
	if err := ks.Load(f, password); err != nil {
		return ks, err
	}

	return ks, err
}

func writeKeyStore(ks keystore.KeyStore, filename string, password []byte) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err = ks.Store(f, password)
	if err != nil {
		log.Fatal(err) //nolint: gocritic
	}
}

func getJKS(jksPath string, jksPassword []byte) (keystore.KeyStore, error) {
	var ks keystore.KeyStore

	// Check if the keystore file already exists
	if _, err := os.Stat(jksPath); err == nil {
		ks, err = readKeyStore(jksPath, jksPassword)
		return ks, err
	}

	// Create a new keystore
	ks = keystore.New()

	// Write the keystore to a file
	jksFile, err := os.Create(jksPath)
	if err != nil {
		return ks, err
	}
	defer jksFile.Close()
	err = ks.Store(jksFile, []byte(jksPassword))
	if err != nil {
		return ks, err
	}

	return ks, nil
}

func readCertsFromFile(certPath, keyPath, caPath string) ([]byte, []byte, []byte, error) {
	var certPEM, keyPEM, caPEM []byte
	var err error
	// Read and parse the certificate
	if strings.Contains(certPath, "-----BEGIN") {
		certPEM = []byte(certPath)
	} else {
		certPEM, err = os.ReadFile(certPath)
		if err != nil {
			return certPEM, keyPEM, caPEM, err
		}
	}
	// Read and parse the private key
	if strings.Contains(keyPath, "-----BEGIN") {
		keyPEM = []byte(keyPath)
	} else {
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			return certPEM, keyPEM, caPEM, err
		}
	}

	if caPath != "" {
		if strings.Contains(caPath, "-----BEGIN") {
			caPEM = []byte(caPath)
		} else {
			caPEM, err = os.ReadFile(caPath)
			if err != nil {
				return certPEM, keyPEM, caPEM, err
			}
		}
	}
	return certPEM, keyPEM, caPEM, err
}

func addKeyToJKS(name string, certPEM []byte, keyPEM []byte, caPEM []byte, jksPath string, jksPassword string) error {
	var err error

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return errors.New("failed to decode private key")
	}

	// Read and parse the CA certificate if provided
	var caCert *x509.Certificate
	if len(caPEM) < 1 {
		caBlock, _ := pem.Decode(caPEM)
		if caBlock == nil || caBlock.Type != "CERTIFICATE" {
			return errors.New("failed to decode CA certificate")
		}
		caCert, err = x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			return err
		}
	}

	ks, err := getJKS(jksPath, []byte(jksPassword))
	if err != nil {
		return err
	}

	// Build the certificate chain
	certChain := []keystore.Certificate{
		{Type: "X509", Content: cert.Raw},
	}
	if caCert != nil {
		certChain = append(certChain, keystore.Certificate{Type: "X509", Content: caCert.Raw})
	}

	// Add the certificate chain and private key to the keystore
	ks.SetPrivateKeyEntry(name, keystore.PrivateKeyEntry{
		PrivateKey:       keyBlock.Bytes,
		CertificateChain: certChain,
		CreationTime:     time.Now(),
	}, []byte(jksPassword))

	writeKeyStore(ks, jksPath, []byte(jksPassword))
	return nil
}

// hasCertChanged checks if the certificate or key are different from the ones in the keystore
func hasCertChanged(name string, certPEM []byte, keyPEM []byte, caPEM []byte, jksPath string, jksPassword string) bool {
	if _, err := os.Stat(jksPath); err != nil {
		if os.IsNotExist(err) {
			return true
		}
	}

	ks, err := readKeyStore(jksPath, []byte("changeit"))
	if err != nil {
		return true
	}

	entry, err := ks.GetPrivateKeyEntry(name, []byte(jksPassword))
	if err != nil {
		if errors.Is(err, keystore.ErrEntryNotFound) {
			return true
		}
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return true
	}
	if !bytes.Equal(keyBlock.Bytes, entry.PrivateKey) {
		fmt.Printf("Key changed: %s\n", name)
		return true
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return true
	}
	certDecoded, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Printf("Error parsing certificate: %s\n", err)
		return true
	}

	for _, cert := range entry.CertificateChain {
		if !bytes.Equal(certDecoded.Raw, cert.Content) {
			return true
		}
	}

	return false
}

func runOnUpdate(command string) (string, error) {
	if command == "" {
		return "", nil
	}

	// FIXME: let the user choose the shell
	cmd := exec.Command("bash", "-c", command)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

// mainProcess is the core function that handles the main logic of the application
func mainProcess(data map[string]interface{}, confFile *string) {
	cfg, err := getFromVals(data)
	if err != nil {
		log.WithError(err).Errorf("Decoding yaml configuration file %s", *confFile)
		return
	}

	changed := false
	for _, cert := range cfg.Certs {
		certPEM, keyPEM, caPEM, err := readCertsFromFile(cert.CertPath, cert.KeyPath, cert.CaPath)
		if err != nil {
			panic(err)
		}

		if !hasCertChanged(cert.Name, certPEM, keyPEM, caPEM, cfg.KeystorePath, cfg.KeystorePass) {
			log.WithFields(logrus.Fields{
				"cert": cert.Name,
				"jks":  cfg.KeystorePath,
			}).Info("Certificate has not changed, skipping.", cert.Name)
			continue
		}

		err = addKeyToJKS(cert.Name, certPEM, keyPEM, caPEM, cfg.KeystorePath, cfg.KeystorePass)
		if err != nil {
			log.WithFields(logrus.Fields{
				"cert": cert.Name,
				"jks":  cfg.KeystorePath,
			}).Error("Creating jks file on ", cfg.KeystorePath, err)
			return
		}
		changed = true
	}
	if changed {
		log.WithFields(logrus.Fields{
			"jks": cfg.KeystorePath,
		}).Info("Keystore updated, running OnUpdate command")
		out, err := runOnUpdate(cfg.OnUpdate)
		if err != nil {
			log.WithError(err).Errorf("Running OnUpdate command %s", cfg.OnUpdate)
			return
		}
		log.Info("OnUpdate command output: ", out)
	}
}

func getenvOrDefault(envKey, defaultVal string) string {
	val := os.Getenv(envKey)
	if val != "" {
		return val
	}
	return defaultVal
}

// main is the entry point of the application. It initializes the logger, parses command-line flags for configuration file path,
// daemon mode, and interval. It reads the configuration file and either runs the main process once or repeatedly as a daemon
// at the specified interval, logging relevant events and errors throughout the process.
func main() {
	// Create a new logger instance (optional, can use the package-level logger)
	log = logrus.New()

	confFile := flag.String("config", getenvOrDefault("CERT2JKS_CONFIG", "tests/example.yaml"), "Path to the configuration file - env: CERT2JKS_CONFIG")
	daemonEnabled := flag.Bool("daemon", getenvOrDefault("CERT2JKS_DAEMON", "false") == "true", "Run as a systemd daemon - env: CERT2JKS_DAEMON")
	daemonInterval := flag.Duration("interval", func() time.Duration {
		env := os.Getenv("CERT2JKS_INTERVAL")
		if env != "" {
			if d, err := time.ParseDuration(env); err == nil {
				return d
			}
		}
		return 43200 * time.Second
	}(), "Interval for the daemon to check for changes (e.g. 12h, 3600s) - env: CERT2JKS_INTERVAL")
	logFormat := flag.String("log-format", getenvOrDefault("CERT2JKS_LOG_FORMAT", "json"), "Log format (json or text) - env: CERT2JKS_LOG_FORMAT")
	logLevel := flag.String("log-level", getenvOrDefault("CERT2JKS_LOG_LEVEL", "info"), "Log level (debug, info, warn, error, fatal, panic) - env: CERT2JKS_LOG_LEVEL")
	flag.Parse()

	// Set the output format (e.g., JSON)
	if *logFormat == "json" {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{})
	}

	// Set the log level
	// Set the log level based on user input
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		log.WithError(err).Errorf("Invalid log level '%s' provided. Defaulting to 'info'.", *logLevel)
		log.SetLevel(logrus.InfoLevel)
	} else {
		log.SetLevel(level)
	}

	if *confFile == "" {
		log.Error("Please provide a configuration file with -config flag")
		return
	}

	log.Debug("Reading configuration file ", *confFile)
	data, err := readConfigFile(*confFile)
	if err != nil {
		log.WithError(err).Errorf("Reading configuration file %s", *confFile)
		return
	}

	if !*daemonEnabled {
		mainProcess(data, confFile)
	} else {
		log.Info("Running as daemon with an interval of ", *daemonInterval)
		for {
			mainProcess(data, confFile)

			// Calculate the next check time
			startTime := time.Now()
			futureTime := startTime.Add(*daemonInterval)
			formattedTime := futureTime.Format("02/01/2006 15:04")

			log.Info("The next check will be at ", formattedTime)
			time.Sleep(*daemonInterval * time.Second)
		}
	}
}
