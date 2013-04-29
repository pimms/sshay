SSHay
=====

This is a barebones "extra credit" SSH-client for a school project, 
and is not in any way shape or form not suitable for actual use.         
Only the _required_ or most convenient _(user-auth: password)_ 
algorithms are supported by SSHay.

----
## SSHay development status
### Transport Layer Protocol
Only the _REQUIRED_ algorithms are supported for all fields. This includes:

- 3DES-cbc for encryption
- SHA-1 for integrity
- DSS for server key format

The client __expects__ the server to support these algorithms,
and the connection will fail if the server does not support any 
of them.

### User Authentication Protocol
For user authentication, the required algorithm - _publickey_ - is 
not supported. Only _password_ is supported. No check is made to 
ensure that the server also supports password-authentication, so
this might be a point of crash&burn.

### Connection Protocol (barely)
Normal key input (almost) always work. "Special" input such as
backspace or the arrow keys are in no way functional yet.

All other defined functionality like X11 and tcp-forwarding is not supported.

### Security Concerns
1.  The server's public key fingerprint is not saved to verify the actual identity of the server.
2.  The MAC is not verified on received packets.
3.  There are more secure ciphers than 3DES.


### Compatibility
SSHay is only tested on Ubuntu 12.04, but should build on run on most UNIX systems.

Dependencies:

- gmp
- pthread
- OpenSSL
