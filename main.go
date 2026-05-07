package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/helmfile/vals"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var log *logrus.Logger

// secret wraps a sensitive string so it does not leak through fmt/log.
type secret string

func (s secret) String() string            { return "[REDACTED]" }
func (s secret) GoString() string          { return "[REDACTED]" }
func (s secret) MarshalYAML() (any, error) { return string(s), nil }
func (s *secret) UnmarshalYAML(value *yaml.Node) error {
	var v string
	if err := value.Decode(&v); err != nil {
		return err
	}
	*s = secret(v)
	return nil
}
func (s secret) Bytes() []byte { return []byte(s) }

type Cert struct {
	Name     string `yaml:"Name"`
	CertPath string `yaml:"Cert"`
	KeyPath  string `yaml:"Key"`
	CaPath   string `yaml:"CA"`
}

type Config struct {
	KeystorePath string `yaml:"KeystorePath"`
	KeystorePass secret `yaml:"KeystorePassword"`
	Certs        []Cert `yaml:"Certs"`
	OnUpdate     string `yaml:"OnUpdate,omitempty"`
	Encoding     string `yaml:"Encoding,omitempty"`
}

func readConfigFile(configFile string) (map[string]any, error) {
	result := make(map[string]any)
	configYaml, err := os.ReadFile(configFile)
	if err != nil {
		return result, err
	}
	if err := yaml.Unmarshal(configYaml, &result); err != nil {
		return result, err
	}
	return result, nil
}

func base64DecodeConfig(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	return string(decoded), nil
}

func getFromVals(cfg map[string]any) (Config, error) {
	var renderedConfig Config

	runtime, err := vals.New(vals.Options{CacheSize: 300})
	if err != nil {
		return renderedConfig, err
	}

	valsRendered, err := runtime.Eval(cfg)
	if err != nil {
		return renderedConfig, err
	}

	// Process Certs before marshalling
	certsRaw, ok := valsRendered["Certs"]
	if ok {
		certs, ok := certsRaw.([]interface{})
		if !ok {
			return renderedConfig, fmt.Errorf("Certs is not a slice")
		}

		for _, certRaw := range certs {
			cert, ok := certRaw.(map[string]interface{})
			if !ok {
				continue
			}

			if crtStr, ok := cert["Cert"].(string); ok {
				decoded, err := base64DecodeConfig(crtStr)
				if err != nil {
					fmt.Printf("Could not decode %s cert as base64\n", cert["Name"])
				} else {
					cert["Cert"] = decoded
				}
			}
		}
	}

	renderedYaml, err := yaml.Marshal(valsRendered)
	if err != nil {
		return renderedConfig, err
	}

	if err := yaml.Unmarshal(renderedYaml, &renderedConfig); err != nil {
		return renderedConfig, err
	}

	return renderedConfig, nil
}

func readKeyStore(filename string, password []byte) (keystore.KeyStore, error) {
	ks := keystore.New()
	f, err := os.Open(filename)
	if err != nil {
		return ks, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.WithError(cerr).Warn("close keystore file")
		}
	}()

	if err := ks.Load(f, password); err != nil {
		return ks, err
	}
	return ks, nil
}

// writeKeyStore writes the keystore atomically with mode 0600.
func writeKeyStore(ks keystore.KeyStore, filename string, password []byte) error {
	dir := filepath.Dir(filename)
	tmp, err := os.CreateTemp(dir, ".jks-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp keystore: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp keystore: %w", err)
	}
	if err := ks.Store(tmp, password); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("store keystore: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp keystore: %w", err)
	}
	if err := os.Rename(tmpName, filename); err != nil {
		cleanup()
		return fmt.Errorf("rename keystore: %w", err)
	}
	return nil
}

func getJKS(jksPath string, jksPassword []byte) (keystore.KeyStore, error) {
	if _, err := os.Stat(jksPath); err == nil {
		return readKeyStore(jksPath, jksPassword)
	} else if !os.IsNotExist(err) {
		return keystore.New(), err
	}

	ks := keystore.New()
	if err := writeKeyStore(ks, jksPath, jksPassword); err != nil {
		return ks, err
	}
	return ks, nil
}

// loadPEM resolves a PEM source. Resolution order:
//  1. Empty -> nil.
//  2. Begins with "-----BEGIN" -> inline PEM.
//  3. Decodes as base64 to inline PEM (vals secret backends sometimes
//     return base64-encoded material) -> decoded bytes.
//  4. Plausible filesystem path (no NUL/newline, <= 4096 bytes) -> read file.
//
// Anything else is an explicit error rather than a silent file read.
func loadPEM(src string) ([]byte, error) {
	if src == "" {
		return nil, nil
	}
	trimmed := strings.TrimSpace(src)
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		return []byte(src), nil
	}

	// Try base64. PEM inside base64 is common when secrets travel through
	// systems that mangle whitespace (Vault, AWS SM, K8s secrets).
	if decoded, ok := tryBase64PEM(trimmed); ok {
		return decoded, nil
	}

	if strings.ContainsAny(src, "\n\r\x00") {
		return nil, errors.New("invalid PEM source: not a valid path and missing BEGIN marker")
	}
	if len(src) > 4096 {
		return nil, errors.New("invalid PEM source: payload too long, not a path, and not base64-encoded PEM")
	}
	return os.ReadFile(filepath.Clean(src))
}

// tryBase64PEM attempts to decode s as base64. Returns the decoded bytes only
// if the result begins with a PEM "-----BEGIN" marker.
func tryBase64PEM(s string) ([]byte, bool) {
	// Strip whitespace inside the candidate.
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
	if len(clean) < 64 {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := enc.DecodeString(clean)
		if err != nil {
			continue
		}
		if bytes.HasPrefix(bytes.TrimSpace(decoded), []byte("-----BEGIN")) {
			return decoded, true
		}
	}
	return nil, false
}

func readCertsFromFile(certPath, keyPath, caPath string) ([]byte, []byte, []byte, error) {
	certPEM, err := loadPEM(certPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := loadPEM(keyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read key: %w", err)
	}
	caPEM, err := loadPEM(caPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read ca: %w", err)
	}
	return certPEM, keyPEM, caPEM, nil
}

// isPrivateKeyPEM accepts PKCS#8, PKCS#1 RSA, and SEC1 EC private key blocks.
func isPrivateKeyPEM(t string) bool {
	switch t {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return true
	}
	return false
}

// parseChain decodes one leaf cert and any additional CA certs from caPEM.
func parseChain(certPEM, caPEM []byte) (*x509.Certificate, []*x509.Certificate, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to decode certificate")
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	var cas []*x509.Certificate
	rest := caPEM
	for len(bytes.TrimSpace(rest)) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse CA: %w", err)
		}
		cas = append(cas, c)
	}
	return leaf, cas, nil
}

func addKeyToJKS(name string, certPEM, keyPEM, caPEM []byte, jksPath string, jksPassword []byte) error {
	leaf, cas, err := parseChain(certPEM, caPEM)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || !isPrivateKeyPEM(keyBlock.Type) {
		return errors.New("failed to decode private key")
	}

	ks, err := getJKS(jksPath, jksPassword)
	if err != nil {
		return err
	}

	chain := []keystore.Certificate{{Type: "X509", Content: leaf.Raw}}
	for _, c := range cas {
		chain = append(chain, keystore.Certificate{Type: "X509", Content: c.Raw})
	}

	if err := ks.SetPrivateKeyEntry(name, keystore.PrivateKeyEntry{
		PrivateKey:       keyBlock.Bytes,
		CertificateChain: chain,
		CreationTime:     time.Now(),
	}, jksPassword); err != nil {
		return fmt.Errorf("set private key entry: %w", err)
	}

	return writeKeyStore(ks, jksPath, jksPassword)
}

// hasCertChanged returns true if the keystore is missing, the entry is missing,
// or any element of the on-disk chain (leaf + CAs) differs from the input.
// Private-key bytes are compared in constant time.
func hasCertChanged(name string, certPEM, keyPEM, caPEM []byte, jksPath string, jksPassword []byte) bool {
	if _, err := os.Stat(jksPath); err != nil {
		return true
	}

	ks, err := readKeyStore(jksPath, jksPassword)
	if err != nil {
		return true
	}

	entry, err := ks.GetPrivateKeyEntry(name, jksPassword)
	if err != nil {
		return true
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || !isPrivateKeyPEM(keyBlock.Type) {
		return true
	}
	if subtle.ConstantTimeCompare(keyBlock.Bytes, entry.PrivateKey) != 1 {
		return true
	}

	leaf, cas, err := parseChain(certPEM, caPEM)
	if err != nil {
		return true
	}

	want := [][]byte{leaf.Raw}
	for _, c := range cas {
		want = append(want, c.Raw)
	}
	if len(want) != len(entry.CertificateChain) {
		return true
	}
	for i, raw := range want {
		if !bytes.Equal(raw, entry.CertificateChain[i].Content) {
			return true
		}
	}
	return false
}

// runOnUpdate runs the configured update command via /bin/sh -c.
// SECURITY: OnUpdate is executed verbatim; treat the config file and any
// vals-resolved sources as fully trusted. The command body is never logged.
func runOnUpdate(command string) (string, error) {
	if command == "" {
		return "", nil
	}
	cmd := exec.Command("/bin/sh", "-c", command)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// sanitizeLogValue strips CR/LF to prevent log-injection from user-supplied YAML.
func sanitizeLogValue(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}

func mainProcess(data map[string]any, confFile *string) {
	cfg, err := getFromVals(data)
	if err != nil {
		log.WithError(err).Errorf("Decoding yaml configuration file %s", *confFile)
		return
	}

	pw := cfg.KeystorePass.Bytes()
	defer zero(pw)

	changed := false
	for _, cert := range cfg.Certs {
		certName := sanitizeLogValue(cert.Name)
		certPEM, keyPEM, caPEM, err := readCertsFromFile(cert.CertPath, cert.KeyPath, cert.CaPath)
		if err != nil {
			log.WithError(err).WithField("cert", certName).Error("Failed to read certificate files")
			continue
		}

		if !hasCertChanged(cert.Name, certPEM, keyPEM, caPEM, cfg.KeystorePath, pw) {
			log.WithFields(logrus.Fields{
				"cert": certName,
				"jks":  cfg.KeystorePath,
			}).Info("Certificate has not changed, skipping")
			continue
		}

		if err := addKeyToJKS(cert.Name, certPEM, keyPEM, caPEM, cfg.KeystorePath, pw); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"cert": certName,
				"jks":  cfg.KeystorePath,
			}).Error("Failed to update keystore")
			return
		}
		changed = true
	}

	if !changed {
		return
	}

	log.WithField("jks", cfg.KeystorePath).Info("Keystore updated, running OnUpdate command")
	out, err := runOnUpdate(cfg.OnUpdate)
	if err != nil {
		log.WithError(err).Error("OnUpdate command failed")
		return
	}
	if out != "" {
		log.Info("OnUpdate command output: ", out)
	}
}

// zero clears a byte slice in place to remove sensitive material from memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func getenvOrDefault(envKey, defaultVal string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return defaultVal
}

func main() {
	log = logrus.New()

	confFile := flag.String("config", getenvOrDefault("CERT2JKS_CONFIG", "tests/example.yaml"), "Path to the configuration file - env: CERT2JKS_CONFIG")
	daemonEnabled := flag.Bool("daemon", getenvOrDefault("CERT2JKS_DAEMON", "false") == "true", "Run as a systemd daemon - env: CERT2JKS_DAEMON")
	daemonInterval := flag.Duration("interval", func() time.Duration {
		if env := os.Getenv("CERT2JKS_INTERVAL"); env != "" {
			if d, err := time.ParseDuration(env); err == nil {
				return d
			}
		}
		return 43200 * time.Second
	}(), "Interval for the daemon to check for changes (e.g. 12h, 3600s) - env: CERT2JKS_INTERVAL")
	logFormat := flag.String("log-format", getenvOrDefault("CERT2JKS_LOG_FORMAT", "json"), "Log format (json or text) - env: CERT2JKS_LOG_FORMAT")
	logLevel := flag.String("log-level", getenvOrDefault("CERT2JKS_LOG_LEVEL", "info"), "Log level (debug, info, warn, error, fatal, panic) - env: CERT2JKS_LOG_LEVEL")
	flag.Parse()

	if *logFormat == "json" {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{})
	}

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
		return
	}

	log.Info("Running as daemon with an interval of ", *daemonInterval)
	for {
		mainProcess(data, confFile)
		next := time.Now().Add(*daemonInterval).Format("02/01/2006 15:04")
		log.Info("The next check will be at ", next)
		time.Sleep(*daemonInterval)
	}
}
