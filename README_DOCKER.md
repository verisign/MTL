# MTL Mode Docker Images
The MTL docker image is dependent on a base cryptographic image which consists of OpenSSL (version 3.5.0+) and LibOQS (version 0.14.0+).

That base image can be built using the pqc_base Dockerfile in this repo via the command ``` docker compose build pqc-base ```

## Building
The MTL Mode container is built using docker and defaults to enabling several underlying signature schemes listed in [README_SCHEMES.md](./README_SCHEMES.md).

The container is built using the compose.yaml file for docker compose:

``` docker compose build mtl-mode ```

Alternatively it can be built directly with docker using the labels and parameters defined in the compose.yaml file.

# Running
This container builds a slim image with the shared librarires for MTL mode. It is not intended to be run standalone but used as a dependency for other containers that have applications that support MTL Mode like LDNS (https://github.com/verisign/mtl-mode-ldns), NSD (https://github.com/verisign/mtl-mode-nsd), or Unbound (https://github.com/verisign/mtl-mode-unbound).

For inspection purposes the container can be run with the following docker command.
```
docker run -it docker.io/library/pqc_mtl_mode:latest  /bin/bash
```
