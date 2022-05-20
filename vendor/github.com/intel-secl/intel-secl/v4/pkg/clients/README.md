# clients

This repository is for holding all client codes to micro services.

Please implement the client code of future services in this repo, \
and the process of moving existing client into this repo is being carried on.

### Install `go` version 1.14.4
The `clients` requires Go version 1.14.4 that has support for `go modules`. The build was validated with the latest version 1.14.4 of `go`. It is recommended that you use 1.14.4 version of `go`. More recent versions may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
tar -xzf go1.14.4.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

# code structure

Please follow the elaborated repository structure when designing new components

```
             ┌-----→  lib-common  ←--┐
             |             ↑         |
          services ( → ) clients     |
                           ↑         |
                      applications---┘
```

- lib-common
    - contains types that are shared across multiple components
    - contains general functions used in multiple components
- services
    - depends on lib-common for shared types
    - depends on client repository if inter-service communication is required
- clients
    - depends on lib-common for shared types
    - should not depend on service repos
- applications
    - depends on clients for accessing services
    - depends on lib-common for shared types

# summary

services | client code status | sharing custom types
---------|--------------------|------------
cms      | implemented  |  no
aas      | implemented  |  yes
