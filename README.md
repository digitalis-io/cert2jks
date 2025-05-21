# cert2jks

`cert2jks` is a Go utility that reads certificates, private keys, and CA certificates from files (or inline PEM), and generates or updates a Java KeyStore (JKS) file. It supports configuration via YAML, can run as a daemon to periodically check for certificate changes, and can execute a custom command when the keystore is updated. This utility is designed for developers and system administrators who need to manage certificates efficiently.

The certificates can be stored to any secrets management backend supported by [helmfile/vals](https://github.com/helmfile/vals?tab=readme-ov-file#supported-backends). See examples below.

## Features

- Reads certificate, key, and CA from files or inline PEM.
- Creates or updates a JKS keystore with the provided credentials.
- Detects changes in certificates/keys and only updates the keystore if needed.
- Supports running as a daemon to periodically check for changes.
- Executes a user-defined command after updating the keystore (e.g., to reload a service).
- Supports configuration templating and secrets management with [helmfile/vals](https://github.com/helmfile/vals).
- Provides detailed usage examples and troubleshooting tips for common issues.

## Configuration

Configuration is provided via a YAML file. Ensure proper YAML syntax and indentation. Example:

```yaml
KeystorePath: keystore.jks
KeystorePassword: changeit
OnUpdate: |-
  echo "Keystore updated"
  systemctl restart my-service
Certs:
  - Name: key1
    Cert:  mycert.crt
    Key: mykey.crt
    CA: myca.crt
  - Name: key2
    Cert: ref+vault://secret/cert#crt
    Key: ref+vault://secret/cert#key
    CA: ref+vault://secret/cert#ca
```

* KeystorePath: Path to the JKS file to create or update.
* KeystorePassword: Password for the JKS file.
* OnUpdate: (Optional) Shell command to run after updating the keystore.
* Certs: List of certificates to add to the keystore.
    * Name: Alias for the key entry in the keystore.
    * Cert: Path to the certificate file (or inline PEM).
    * Key: Path to the private key file (or inline PEM).
    * CA: (Optional) Path to the CA certificate file (or inline PEM).

The whole configuration is parsed through [helmfile/vals](https://github.com/helmfile/vals?tab=readme-ov-file#supported-backends) which means you can add
entries to any suported encrypted backend for any field. The complex example below combines three different encrypted storages
to obtain the `KeystorePassword` from [AWS](https://aws.amazon.com/secrets-manager/),
the script to run from [S3](https://aws.amazon.com/s3/) and the certs from [Hashicorp Vault](https://developer.hashicorp.com/vault):

```yaml
KeystorePath: /opt/myApp/keystore.jks
KeystorePassword: ref+awssecrets://PATH/TO/SECRET[?region=REGION&role_arn=ASSUMED_ROLE_ARN]#/KeystorePassword
OnUpdate: ref+s3://BUCKET/KEY/OF/OBJECT[?region=REGION&profile=AWS_PROFILE&role_arn=ASSUMED_ROLE_ARN&version_id=ID]
Certs:
  - Name: key1
    Cert: ref+vault://secret/cert#crt
    Key: ref+vault://secret/cert#key
    CA: ref+vault://secret/cert#ca
```

## Usage

```sh
make
./dist/cert2jks -config path/to/config.yaml [-daemon]
```

You can run this command for example:

- Using a cronjob: create a cronjob for example on `/etc/cron.daily/cert2jks`
- Using systemd as a [service](./resources/cert2jks.service)
- Manually

### Docker

```sh
docker run -d --name cert2jks -v /config.yaml:/app/config.yaml ghcr.io/digitalis-io/cert2jks:latest
```
This command mounts the configuration file into the container, allowing the application to access it.

### Options

```sh
Usage of cert2jks
  -config string
    	Path to the configuration file (default "tests/example.yaml")
  -daemon
    	Run as a systemd daemon
  -interval duration
    	Interval in seconds for the daemon to check for changes (default 12h0m0s)
  -log-format string
        Log format (json or text) (default "json")
  -log-level string
        Log level (debug, info, warn, error, fatal, panic) (default "info")
```

## How it works

* Reads the configuration file and renders it with vals if needed.
* For each certificate entry:
    * Reads the certificate, key, and optional CA.
    * Checks if the certificate or key has changed in the keystore.
    * If changed, updates the keystore with the new entry.
    * If any changes were made, runs the OnUpdate command.

## Dependencies

- github.com/pavlo-v-chernykh/keystore-go/v4: Library for managing Java KeyStores.
- github.com/helmfile/vals: Library for configuration templating and secrets management.
- github.com/sirupsen/logrus: Structured logger for Go.
- gopkg.in/yaml.v3: YAML support for Go.
