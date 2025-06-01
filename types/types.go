package types

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
