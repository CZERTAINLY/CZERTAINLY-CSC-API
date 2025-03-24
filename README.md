# CZERTAINLY CSC API

This repository contains implementation of the CZERTAINLY CSC API. For more information about the CSC API, refer to the [Cloud Signature Consortium](https://cloudsignatureconsortium.org) website, or the [CZERTAINLY documentation](https://docs.czertainly.com/docs/signing/csc-component/overview).

## Prerequisites

The project requires the following tools to be installed:
- **Docker** (for development and testing)

## Building the project

The project is built using the Maven build tool. To build the project, run the following command:

```bash
mvn clean package
```

## Running the project

Running the project requires a configuration files. The main configuration file should be named `application.yml` and should be placed in the `src/main/resources` directory or in as the `/opt/cscapi/application.yml` in the associated container.

## Development

For the development, you can utilize existing docker compose configuration. The docker compose configuration is available in the [`docker-compose.yml`](./development/docker-compose.yml) file.

To start the development environment, update the compose configuration with the required environment variables and run the following command:

```bash
docker-compose -f development/docker-compose.yml up
```
