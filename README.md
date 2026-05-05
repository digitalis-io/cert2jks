<p align="center">
  <a href="https://digitalis.io">
    <img src="https://digitalis-marketplace-assets.s3.us-east-1.amazonaws.com/DigitalisDigital_DigitalisFullLogoGradient+-+medium.png" alt="Digitalis.IO" width="300">
  </a>
</p>

<p align="center">
  <em>Built and maintained by <a href="https://digitalis.io">Digitalis.IO</a></em>
</p>

# cert2jks

`cert2jks` is a Go utility that reads certificates, private keys, and CA certificates from files (or inline PEM), and generates or updates a Java KeyStore (JKS) file. It supports configuration via YAML, can run as a daemon to periodically check for certificate changes, and can execute a custom command when the keystore is updated.

Certificates can be sourced from any secrets-management backend supported by [helmfile/vals](https://github.com/helmfile/vals?tab=readme-ov-file#supported-backends). See examples below.

## Features

- Reads certificate, key, and CA from files or inline PEM.
- Creates or updates a JKS keystore with the provided credentials.
- Detects changes in certificates/keys and only updates the keystore when needed.
- Supports running as a daemon to periodically check for changes.
- Executes a user-defined command after updating the keystore (e.g. to reload a service).
- Supports configuration templating and secrets management with [helmfile/vals](https://github.com/helmfile/vals).

## Configuration

Configuration is provided via a YAML file. Example:

```yaml
KeystorePath: keystore.jks
KeystorePassword: changeit
OnUpdate: |-
  echo "Keystore updated"
  systemctl restart my-service
Certs:
  - Name: key1
    Cert: mycert.crt
    Key: mykey.crt
    CA: myca.crt
  - Name: key2
    Cert: ref+vault://secret/cert#crt
    Key: ref+vault://secret/cert#key
    CA: ref+vault://secret/cert#ca
```

| Field | Required | Description |
|-------|----------|-------------|
| `KeystorePath` | Yes | Path to the JKS file to create or update. |
| `KeystorePassword` | Yes | Password for the JKS file. |
| `OnUpdate` | No | Shell command to run after updating the keystore. |
| `Certs` | Yes | List of certificates to add to the keystore. |
| `Certs[].Name` | Yes | Alias for the key entry in the keystore. |
| `Certs[].Cert` | Yes | Path to the certificate file (or inline PEM). |
| `Certs[].Key` | Yes | Path to the private key file (or inline PEM). |
| `Certs[].CA` | No | Path to the CA certificate file (or inline PEM). |

The whole configuration is parsed through [helmfile/vals](https://github.com/helmfile/vals?tab=readme-ov-file#supported-backends), so any field may reference any supported encrypted backend. The example below combines three different backends — the `KeystorePassword` from [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), the `OnUpdate` script from [S3](https://aws.amazon.com/s3/), and the certs from [HashiCorp Vault](https://developer.hashicorp.com/vault):

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

Run options:

- As a cronjob (e.g. `/etc/cron.daily/cert2jks`)
- As a systemd [service](./resources/cert2jks.service)
- Manually

### Docker

```sh
docker run -d --name cert2jks -v /config.yaml:/app/config.yaml ghcr.io/digitalis-io/cert2jks:latest
```

### Options

```sh
Usage of cert2jks
  -config string
        Path to the configuration file - env: CERT2JKS_CONFIG (default "tests/example.yaml")
  -daemon
        Run as a systemd daemon - env: CERT2JKS_DAEMON
  -interval duration
        Interval for the daemon to check for changes (e.g. 12h, 3600s) - env: CERT2JKS_INTERVAL (default 12h0m0s)
  -log-format string
        Log format (json or text) - env: CERT2JKS_LOG_FORMAT (default "json")
  -log-level string
        Log level (debug, info, warn, error, fatal, panic) - env: CERT2JKS_LOG_LEVEL (default "info")
```

All flags can also be set via environment variables (shown above).

## How it works

- Reads the configuration file and renders it with `vals`.
- For each certificate entry:
  - Reads the certificate, key, and optional CA.
  - Checks whether the certificate or key has changed against the keystore entry.
  - If changed, updates the keystore with the new entry.
- If any changes were made, runs the `OnUpdate` command.

## Dependencies

- [github.com/pavlo-v-chernykh/keystore-go/v4](https://github.com/pavlo-v-chernykh/keystore-go) — Java KeyStore management.
- [github.com/helmfile/vals](https://github.com/helmfile/vals) — configuration templating and secrets backends.
- [github.com/sirupsen/logrus](https://github.com/sirupsen/logrus) — structured logging.
- [gopkg.in/yaml.v3](https://gopkg.in/yaml.v3) — YAML parsing.

## About Digitalis

[Digitalis](https://digitalis.io) is a cloud-native technology services company specialising in data engineering, DevOps, and digital transformation. With deep expertise in Apache Kafka, Apache Cassandra, Kubernetes, RabbitMQ, and many more open-source technologies, Digitalis helps organisations design, deploy, and operate resilient data infrastructure at scale.

This project is maintained by the team at [Digitalis](https://digitalis.io). For enterprise support, consulting, or managed services, visit [digitalis.io](https://digitalis.io) or [contact us](https://digitalis.io/contact).

## License

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE) for details.
