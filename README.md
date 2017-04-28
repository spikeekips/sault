# sault

sault is the *reverse proxy* for the ssh authentication. sault supports most of the available ssh usabilities like,
* session
* run remote commands
* port forwarding
* x11 forwarding(not yet fully tested, but it may be works)

For security reason, sault only supports the public key authentication for the user ssh client and for protected ssh host.

## Build

```
$ go build -v cmd/sault.go
```

## Test

```
$ go test ./... -v
```

## Run

```
$ ./sault
```

## Configuration

This is sample configuration file.
```
[server]
bind = ":2222"
host_key_path = "/Volumes/Userland/Users/spikeekips/workspace/sault/src/github.com/spikeekips/sault/host.key"
global_client_key_path = "/Volumes/Userland/Users/spikeekips/workspace/sault/src/github.com/spikeekips/sault/client.key"

[log]
format = "text"
level = "debug"
output = "stdout"

[registry]
type = "file"

[registry.source.file]
path = "/Volumes/Userland/Users/spikeekips/workspace/sault/src/github.com/spikeekips/sault/registry.toml"
```

sault tries to load multiple configuration files from directory, so you can set the directories, which contain the configuration files.

```
$ ls -l /sault-base
total 0
-rw-r--r--  1 spikeekips  wheel  0 Apr 29 03:48 00-base.conf
-rw-r--r--  1 spikeekips  wheel  0 Apr 29 03:48 01-base.conf

$ ls -l /sault-prod
total 0
-rw-r--r--  1 spikeekips  wheel  0 Apr 29 03:48 00-prod.conf
-rw-r--r--  1 spikeekips  wheel  0 Apr 29 03:48 01-prod.conf

$ ./sault -configDir /sault-base -configDir /sault-production
```

This will load the configurations from /sault-base and then, /sault-production. The multiple statements can be allowed. The following files will be loaded as configuration by order of file names.

```
/sault-base/00-base.conf
/sault-base/01-base.conf
/sault-prod/00-prod.conf
/sault-prod/01-prod.conf
```

> The dot-prefixed hidden fiels will not be loaded.

> The relative path in configuration will be based on the last config directory.
