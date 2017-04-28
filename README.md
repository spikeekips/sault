# sault

sault is the *reverse proxy* for the ssh authentication. sault supports most of the available ssh usabilities like,
* session
* run remote commands
* port forwarding
* x11 forwarding(not yet fully tested, but it may be works)

For security reason, sault only supports the public key authentication for the user ssh client and for protected ssh host.
