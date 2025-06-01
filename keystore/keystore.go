package keystore

import (
	"os"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

type KeystoreManager interface {
	ReadKeyStore(filename string, password []byte) (keystore.KeyStore, error)
	WriteKeyStore(ks keystore.KeyStore, filename string, password []byte) error
	GetOrCreateKeyStore(path string, password []byte) (keystore.KeyStore, error)
}

type DefaultKeystoreManager struct{}

func (km *DefaultKeystoreManager) ReadKeyStore(filename string, password []byte) (keystore.KeyStore, error) {
	var ks keystore.KeyStore
	f, err := os.Open(filename)
	if err != nil {
		return ks, err
	}
	defer f.Close()

	ks = keystore.New()
	if err := ks.Load(f, password); err != nil {
		return ks, err
	}

	return ks, nil
}

func (km *DefaultKeystoreManager) WriteKeyStore(ks keystore.KeyStore, filename string, password []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return ks.Store(f, password)
}

func (km *DefaultKeystoreManager) GetOrCreateKeyStore(path string, password []byte) (keystore.KeyStore, error) {
	if _, err := os.Stat(path); err == nil {
		return km.ReadKeyStore(path, password)
	}

	ks := keystore.New()
	if err := km.WriteKeyStore(ks, path, password); err != nil {
		return ks, err
	}

	return ks, nil
}
