## Fast Guide to Choose Arguments
**I want to bypass censorship**
* Transfer Mode: ***Always use `wss`***. Try to issue a valid certificate. For example you can use [certbot](https://certbot.eff.org/).
* Encryption: ChaCha20
* KeyAgreement: SHA-256 or PBKDF2

If websocket is not available, it's good to use SHA-256 as key agreement because it does not have a handshake. (It's harder to detect it) And don't change Encryption method.

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
## Technical Stuff
### Transfer Modes
This app supports 3 ways to transfer your data:
1. `tcp`: Uses RAW tcp to transfer your data. Use this method if you want some speed.
2. `ws`: Uses unencrypted websocket (however your packets are encrypted) to transfer your data. (You might be able to use this method with CDN)
3. `wss`: Uses secure websocket to transfer your data. If you want to use this method, you must issue an certificate. (Or sign one yourself) **ALWAYS USE THIS METHOD IF YOU WANT TO ESCAPE CENSORSHIP**
#### How to Generate Self Signed Certificate
With openssl you can generate one. [Read here](https://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl)
### Handshake
Overally if there is an decryption problem, server drops the connection.
#### SHA-256
There is no handshake for SHA-256. Both client and server hash the password and try to encrypt and decrypt the data with that key. If decryption fails, server terminates the connection.
#### PBKDF2 Handshake
When the connection establishes, server sends 8 bytes to client which is salt of the algorithm. Client and server generate the same secret with the same password. No RSA keys are used.
#### X25519, scrypt and Argon2ID
When the server starts, server generates a RSA-2048 key pair. When a client connects to server, server sends it's public key to client. Client must encrypt it's password 
### Key Derivation Algorithms
After that the server verified the handshake, server uses one of the key derivation algorithms to generate same secret on server and client.
This app supports 5 key derivation methods. Each has their own benefits and downsides. Here a list for you to see which one to use:
1. `SHA-256`: In this method both server and client hash the password using SHA-256 to generate a shared key for encryption and decryption. This means that all of the connections use the same encryption key that is not a good idea. Plus the only way that server realizes that client's password is not correct, is from the first incoming packet when server cannot decrypt it. (server drops the connection). On the other hand, note that SHA-256 handshake is blazingly fast.
2. `X25519`: This is a combination of RSA-2048 and X25519 key agreement algorithm. At start up of the server, it generates a random RSA-2048 and X25519 key pair. When a client wants to connect, server sends the PEM encoded of RSA-2048 public key to client (which is 459 bytes) and public key of X25519 (which is 32 bytes; Totally 491 bytes are send to client). After client receives this, at first it generates a X25519 key pair. Client encrypts the password with server's public key (256 bytes), concats the public key of his own (32 bytes) and sends it to server. This method is not good if you want to use this software to evade censorship. However it's nearly fast and secure.
3. `PBKDF2`: PBKDF2 implements the key derivation function PBKDF2 as defined in RFC 2898 / PKCS #5 v2.0. It uses HMAC-SHA-1 based PBKDF2 with 16384 iterations. For the handshake, server simply generates 8 random bytes and sends them to client as salt. PBKDF2 with this iterations is generally fast but not very secure.
4. `scrypt`: scrypt is a memory hard algorithm. Meaning that the handshake eats a lot of your ram. In this program I use N=16384, r=8 and p=1. The memory usage for each handshake is 16 megabytes. (after the handshake GC will take care of memory). Just like PBKDF2, on handshake server sends an 8 byte nonce to client in handshake. This method is secure but it is really vulnerable to DDOS attacks and attackers can fuck up your server's ram.
5. `Argon2ID`: Another strong algorithm for key derivation. This is also a memory hard algorithm. It uses 16MB of ram with times=10 and threads=2. This algorithm is very secure to Brute Force attacks however this one also is vulnerable to DDOS attacks. 8 byte nonce is used and server sends it to client at the handshake.

Default of the application is PBKDF2