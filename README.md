# Software Cryptography Provider

> This repository is part of the commercial open-source project ILM. You can find more information about the project at the [ILM](https://github.com/OmniTrustILM/ilm) repository, including the contribution guide.

Software Cryptography Provider `Connector` is the implementation of the following `Function Groups` and `Kinds`:

| Function Group          | Kind   |
|-------------------------|--------|
| `Cryptography Provider` | `SOFT` |

Software Cryptography Provider implements cryptographic key management function based on the software keystore managed data. Therefore, it is not recommended to use this provider for the production environment, where you require higher protection of the cryptographic keys. The Software Cryptography Provider is intended for the development and testing purposes.

It is compatible with the `Cryptography Provider` interface. This entity provider utilizes the SSH authorized connection with the servers and provider the location configuration of the keystore with access to generate and manipulate the content.

Software Cryptography Provider `Connector` allows you to perform the following operations:
- Manage Token instances
- Manage cryptographic Keys
- Request cryptographic operations like encryption, decryption, signing, verification

## Database requirements

Software Cryptography Provider `Connector` requires the PostgreSQL database to store the data. (at lease version 12+)

## Supported key algorithms

Software Cryptography Provider `Connector` supports the following asymmetric algorithms:

| Algorithm | Type       | Key Properties                                                                                                                                        |
|-----------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| `RSA`     | Asymmetric | Key lengths `1024`, `2048`, `4096`                                                                                                                    |
| `ECDSA`   | Asymmetric | Named curves `secp192r1`, `secp224r1`, `secp256r1`, `secp384r1`, `secp521r1`                                                                          |
| `FALCON`  | Asymmetric | With `512` and `1024` degrees spec                                                                                                                    |
| `ML-DSA`  | Asymmetric | Lattice-based and the primary signature algorithm standardised by NIST - [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)         |
| `SLH-DSA` | Asymmetric | Stateless hash-based signature algorithm standardised by NIST - [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)                  |
| `ML-KEM`  | Asymmetric | Lattice-based and the primary key encapsulation mechanism standardised by NIST - [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) |

> Note: Symmetric keys are not supported by this `Connector`.

## Interfaces

Software Cryptography Provider implements `Cryptography Provider` interfaces. To learn more about the interfaces and end points, refer to the [Interfaces](https://github.com/OmniTrustILM/interfaces).

For more information, please refer to the [documentation](https://docs.otilm.com).

## Docker container

Software Cryptography Provider `Connector` is provided as a Docker container. Use the `hub.omnitrustregistry.com/ilm/software-cryptography-provider:tagname` to pull the required image from the repository. It can be configured using the following environment variables:

| Variable                 | Description                                                         | Required                                           | Default value |
|--------------------------|---------------------------------------------------------------------|----------------------------------------------------|---------------|
| `JDBC_URL`               | JDBC URL for database access                                        | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `JDBC_USERNAME`          | Username to access the database                                     | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `JDBC_PASSWORD`          | Password to access the database                                     | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `DB_SCHEMA`              | Database schema to use                                              | ![](https://img.shields.io/badge/-NO-red.svg)      | `softcp`      |
| `PORT`                   | Port where the service is exposed                                   | ![](https://img.shields.io/badge/-NO-red.svg)      | `8080`        |
| `TOKEN_DELETE_ON_REMOVE` | If the token should be deleted or kept in the database when removed | ![](https://img.shields.io/badge/-NO-red.svg)      | `false`       |
| `JAVA_OPTS`              | Customize Java system properties for running application            | ![](https://img.shields.io/badge/-NO-red.svg)      | `N/A`         |