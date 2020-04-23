# Secure Forwarder
Securely forward your packets over internet.

## Features
* Encrypts your packets with AES-GCM-256 or ChaCha20-Poly1305
* Strong key agreements (if you like)
* Forward over websocket (or secure websocket)
* Helps you avoid censorship when you combine this application with SOCKS proxy

## Usage
### Server
Here is a simple usage for server:
```bash
./SecureForwarder --to "127.0.0.1:1080" --port 8080 --password "pass" --encryption aes --type ws server
```
This command, starts the proxy on 0.0.0.0:8080 and sends all incoming packets to "127.0.0.1:1080". It uses websocket as transmission protocol, PBKDF2 as key agreement (default value) and AES-GCM as encryption method.

While using secure websocket, application searches for `cert.pem` and `key.pem` in current directory to use them as certificates. You can manually set them using --cert and --key arguments that come after the verb "server". Example:
```bash
./SecureForwarder --to "127.0.0.1:1080" --port 443 --password "pass" --type wss server --key key1.pem --cert cert1.pem
```
### Client
Example:
```bash
./SecureForwarder --to "1.1.1.1:8080" --port 1080 --password "pass" --encryption aes --type ws client
```
You can see that I only set my server's address and just change the verb "client" to "server"

If you use self signed certificates, in client you should pass the `trust` argument after client. Example:
```bash
./SecureForwarder --to "1.1.1.1:443" --port 1080 --password "pass" --type wss client --trust
```
## Fast Guide to Choose Arguments
**I want speed**
* Transfer Mode: TCP
* Encryption: XOR
* KeyAgreement: SHA-256

**I want something balanced**
* Transfer Mode: TCP or Websocket
* Encryption: ChaCha20
* KeyAgreement: X25519

**I want security**
* Transfer Mode: wss
* Encryption: AES or ChaCha
* KeyAgreement: Argon2

**I want to bypass censorship**
* Transfer Mode: ***Always use `wss`***. Try to issue a valid certificate. For example you can use [certbot](https://certbot.eff.org/).
* Encryption: ChaCha20
* KeyAgreement: SHA-256 or PBKDF2

If websocket is not available, it's good to use SHA-256 as key agreement because it does not have a handshake. (It's harder to detect it) And don't change Encryption method.
## Technical Stuff
### Transfer Modes
This app supports 3 ways to transfer your data:
1. `tcp`: Uses RAW tcp to transfer your data. Use this method if you want some speed.
2. `ws`: Uses unencrypted websocket (however your packets are encrypted) to transfer your data. (You might be able to use this method with CDN)
3. `wss`: Uses secure websocket to transfer your data. If you want to use this method, you must issue an certificate. (Or sign one yourself) **ALWAYS USE THIS METHOD IF YOU WANT TO ESCAPE CENSORSHIP**
#### How to Generate Self Signed Certificate
With openssl you can generate one. [Read here](https://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl)
#### Generate using Certbot
https://www.linode.com/docs/security/ssl/install-lets-encrypt-to-create-ssl-certificates/
### Handshake
Overally if there is an decryption problem, server drops the connection.
#### SHA-256
There is no handshake for SHA-256. Both client and server hash the password and try to encrypt and decrypt the data with that key. If decryption fails, server terminates the connection.
#### X25519
When the server starts, server generates a RSA-2048 key pair (default size). When a client connects to server, server sends it's public key to client (PEM format). Client must encrypt it's password with it and send it back to server. If the password was ok, server generates an X25519 key pair. Server sends it's public key to client. Client also creates one key pair and sends the public key to server. Now they both do the agreement and generate a shared key.
#### PBKDF2 Handshake
There is 2 things that may happen at the handshake client:
1. The first packet of client starts with 0 in binary. This means that this is a handshake packet. There is no RSA-Password verification for this algorithm. Server sends an 8-byte salt to client for the key derivation. Then server sends 8 more bytes, that is the id of this client. The id always starts with 1 in binary. Server saves the ID with the generated key in memory.
2. The first packet of client starts with 1 in binary. This packet is the id of the user. Server loads the id from in memory database and uses it.
#### Scrypt and Argon2ID
These two algorithms are just like PBKDF2, but they require the RSA password verification.
Again we have to possibilities for first packet:
1. It starts with 0 in binary. This means that this is a handshake packet. Server sends the RSA public key to client in PEM format. Client encrypts it's password with the public key and sends it back to server. Sever checks the password. If it's ok, server sends a 8-byte salt (scrypt) or 16-byte salt (argon2) to client and the key agreement is done.  Then server sends 8 more bytes, that is the id of this client. The id always starts with 1 in binary. Server saves the ID with the generated key in memory.
2. It starts with 1 in binary. This means that this is id. Servers receives the id and check's it's database for the key.
### Key Derivation Algorithms
After that the server verified the handshake, server uses one of the key derivation algorithms to generate same secret on server and client.
This app supports 5 key derivation methods. Each has their own benefits and downsides. Here a list for you to see which one to use:
1. `SHA-256`: In this method, both server and client hash the password using SHA-256 to generate a shared key for encryption and decryption. This means that all of the connections use the same encryption key that is not a good idea. Plus the only way that server realizes that client's password is not correct, is from the first incoming packet when server cannot decrypt it. (server drops the connection). On the other hand, note that SHA-256 handshake is blazingly fast.
2. `X25519`: Using X25519 key agreement algorithm with RSA encryption to generate shared keys. This method is fast and secure. However gives a lot of fingerprint for DPI.
3. `PBKDF2`: PBKDF2 implements the key derivation function PBKDF2 as defined in RFC 2898 / PKCS #5 v2.0. It uses HMAC-SHA-1 based PBKDF2 with 16384 iterations. An 8 byte salt is used. PBKDF2 with this iterations is generally fast but not very secure.
4. `scrypt`: scrypt is a memory hard algorithm. Meaning that the handshake eats a lot of your ram. In this program I use N=16384, r=8 and p=1. The memory usage for each handshake is 16 megabytes. (after the handshake GC will take care of memory). Just like PBKDF2, on handshake server sends an 8 byte nonce to client in handshake. This method is secure but slow.
5. `Argon2ID`: Another strong algorithm for key derivation. This is also a memory hard algorithm. It uses 16MB of ram with times=10 and threads=2. This algorithm is very secure to Brute Force attacks however very slow. 16 byte nonce is used and server sends it to client at the handshake.

Default key agreement is PBKDF2

### Encryption
Each packet is encrypted. This app supports 3 different encryption algorithms.
1. `XOR`: Encrypts each packet with raw xor operation. Key is 32 bytes. It's stored in a 32 byte array. The first byte of packet is xored to the first key byte and so on. The 33th byte of packet is encrypted with the first byte of key. XOR is generally fast but unsecure.
2. `AES-GCM-256`: Uses AES with 256 key and 12 bytes of salt to encrypt your data. On a modern computer (and not phones) there is something called AES-NI that hugely speeds up AES. If you don't want to use this app on a phone, it might be a good idea to use this. This algorithm is very secure.
3. `Chacha20-Poly1305`: Uses chacha20 with poly1305 message authentication to encrypt your data. It's faster on the devices that does not support AES-NI. This algorithm is very secure.

Default is Chacha20-Poly1305
## Benchmarks
These benchmarks are done with iperf3 on Intel i7-4790K. One core is used only for server and client. Both are compiled with GO 1.14. Buffer sizes are unchanged.
### Transfer Speed
Key agreement are not important here because they don't affect transfer speed.

#### XOR Cipher
* `TransferType=tcp`: 5.17 Gbits/sec
* `TransferType=ws`: 2.61 Gbits/sec
* `TransferType=wss`: 2.25 Gbits/sec
#### ChaCha20 Cipher
* `TransferType=tcp`: 4.63 Gbits/sec
* `TransferType=ws`: 2.93 Gbits/sec
* `TransferType=wss`: 3.00 Gbits/sec
#### AES Cipher (Note that my CPU does support AES-NI)
* `TransferType=tcp`: 5.06 Gbits/sec
* `TransferType=ws`: 3.12 Gbits/sec
* `TransferType=wss`: 3.16 Gbits/sec

### Key agreement speeds
I just run [this](https://gist.github.com/HirbodBehnam/2223072aff7530efbcda745c1d25250b) script on my pc to benchmark them. Here is the result:
```text
Key size 2048
========= sha 256 =========
0s
========= rsa + x25519 =========
1.9872ms
========= pbkdf2 =========
12.0074ms
========= rsa + scrypt =========
39.9874ms
========= rsa + argon2 =========
54.983ms
```

and I ran one on my mobile (Huawei Mate 10) using Termux and Go 13.8
```text
Key size 2048
========= sha 256 =========
14.063µs
========= rsa + x25519 =========
7.366666ms
========= pbkdf2 =========
10.59948ms
========= rsa + scrypt =========
226.360417ms
========= rsa + argon2 =========
442.169271ms
```
