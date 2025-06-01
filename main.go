package main

import (
	"flag"
	"os"
	"os/exec"
	"time"

	"github.com/helmfile/vals"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/digitalis-io/cert2jks/cert"
	cert2jksKeystore "github.com/digitalis-io/cert2jks/keystore"
	"github.com/digitalis-io/cert2jks/types"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

var (
	log = logrus.New()
	km  = &cert2jksKeystore.DefaultKeystoreManager{}
)

func setupLogger(format, level string) {
	if format == "json" {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{})
	}

	if lvl, err := logrus.ParseLevel(level); err == nil {
		log.SetLevel(lvl)
	}
}

func processConfig(configFile string) (*types.Config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var rawConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return nil, err
	}

	runtime, err := vals.New(vals.Options{CacheSize: 300})
	if err != nil {
		return nil, err
	}

	rendered, err := runtime.Eval(rawConfig)
	if err != nil {
		return nil, err
	}

	renderedYaml, err := yaml.Marshal(rendered)
	if err != nil {
		return nil, err
	}

	var config types.Config
	if err := yaml.Unmarshal(renderedYaml, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func processCertificate(certConfig types.Cert, keystorePath, keystorePass string) (bool, error) {
	certPEM, err := cert.ReadPEMFile(certConfig.CertPath)
	if err != nil {
		return false, err
	}

	keyPEM, err := cert.ReadPEMFile(certConfig.KeyPath)
	if err != nil {
		return false, err
	}

	var caPEM []byte
	if certConfig.CaPath != "" {
		caPEM, err = cert.ReadPEMFile(certConfig.CaPath)
		if err != nil {
			return false, err
		}
	}

	certData, err := cert.ParseCertificateData(certPEM, keyPEM, caPEM)
	if err != nil {
		return false, err
	}

	ks, err := km.GetOrCreateKeyStore(keystorePath, []byte(keystorePass))
	if err != nil {
		return false, err
	}

	// Add certificate to keystore
	certChain := []keystore.Certificate{{
		Type:    "X509",
		Content: certData.Certificate.Raw,
	}}

	if certData.CACertificate != nil {
		certChain = append(certChain, keystore.Certificate{
			Type:    "X509",
			Content: certData.CACertificate.Raw,
		})
	}

	ks.SetPrivateKeyEntry(certConfig.Name, keystore.PrivateKeyEntry{
		PrivateKey:       certData.PrivateKey,
		CertificateChain: certChain,
		CreationTime:     time.Now(),
	}, []byte(keystorePass))

	return true, km.WriteKeyStore(ks, keystorePath, []byte(keystorePass))
}

func main() {
	confFile := flag.String("config", os.Getenv("CERT2JKS_CONFIG"), "Config file path")
	daemonMode := flag.Bool("daemon", false, "Run in daemon mode")
	interval := flag.Duration("interval", 12*time.Hour, "Check interval")
	logFormat := flag.String("log-format", "json", "Log format (json or text)")
	logLevel := flag.String("log-level", "info", "Log level")
	flag.Parse()

	setupLogger(*logFormat, *logLevel)

	config, err := processConfig(*confFile)
	if err != nil {
		log.WithError(err).Fatal("Failed to process config")
	}

	for !*daemonMode {
		if err := processAllCertificates(config); err != nil {
			log.WithError(err).Error("Failed to process certificates")
		}

		if *daemonMode {
			log.Infof("Next check at %s", time.Now().Add(*interval).Format("02/01/2006 15:04"))
			time.Sleep(*interval)
		} else {
			break
		}
	}
}

func processAllCertificates(config *types.Config) error {
	changed := false

	for _, cert := range config.Certs {
		certChanged, err := processCertificate(cert, config.KeystorePath, config.KeystorePass)
		if err != nil {
			return err
		}
		changed = changed || certChanged
	}

	if changed && config.OnUpdate != "" {
		cmd := exec.Command("bash", "-c", config.OnUpdate)
		if out, err := cmd.CombinedOutput(); err != nil {
			return err
		} else {
			log.Info("OnUpdate command output: ", string(out))
		}
	}

	return nil
}
