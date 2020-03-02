package main

import (
	"SecureForwarder/crypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	x25519 "github.com/HirbodBehnam/EasyX25519"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
)

// all clients are redirected here
func WebsocketBase(w http.ResponseWriter, r *http.Request) {
	// at first accept the websocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Cannot upgrade: ", err.Error())
		return
	}
	defer conn.Close()
	log.Trace("New connection from ", r.RemoteAddr)

	// do the handshake just like tcp
	salt := make([]byte, 8)
	var key []byte // is always 256 bit

	// check the id for these algorithms
	if KeyAgreement == "pbkdf2" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" {
		_, idStart, err := conn.ReadMessage() // read the id
		if err != nil {
			log.Error("Cannot read id from client: ", err.Error())
			return
		}
		// check if this a handshake packet or client is using an id; Handshake packet starts with 0 in binary. However id always starts with 1
		if idStart[0]&128 == 128 { // 128 = 10000000 in binary; 1 means id; Check the id
			if k, exists := IdAndKeys.Get(string(idStart)); exists {
				key = k.([]byte) // key is always a byte array
				goto startTransfer
			}
		}
		// otherwise just continue to handshake
	}

	// perform rsa handshake
	if KeyAgreement == "x25519" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" {
		err = conn.WriteMessage(websocket.TextMessage, RSAPublicPem) // send the public key to client
		if err != nil {
			log.Error("Cannot write to client: ", err.Error())
			return
		}
		{ // read the client's response that must be RSA encrypted password
			_, userPass, err := conn.ReadMessage()
			if err != nil {
				log.Error("Cannot write to client: ", err.Error())
				return
			}
			// try to decrypt the password
			decrypted, err := crypt.RSADecryptWithPrivateKey(userPass, RSAPrivateKey)
			if err != nil {
				log.Error("Invalid handshake from ", conn.RemoteAddr())
				return
			}
			// check if the password was correct
			if string(decrypted) != Password {
				log.Error("Invalid password from ", conn.RemoteAddr())
				return
			}
		}
	}
	// if code reaches here, the handshake was ok!
	// generate a salt for key derivation it's not used in sha-256 and x25519
	// generate the key derivation if needed
	switch KeyAgreement {
	case "sha-256":
		key = []byte(Password) // that's it :D
		goto startTransfer
	case "x25519": // this type is little different
		// at first generate a x25519 key pair (client also creates one meanwhile)
		xKey, err := x25519.NewX25519()
		if err != nil {
			log.Error("Cannot generate X25519 key pair: ", err.Error())
			return
		}
		// send the public key to client
		err = conn.WriteMessage(websocket.BinaryMessage, xKey.PublicKey)
		if err != nil {
			log.Error("Cannot send public key to client: ", err.Error())
			return
		}
		// get the public key of the user
		_, otherPub, err := conn.ReadMessage()
		if err != nil {
			log.Error("Cannot get client's X25519 public key: ", err.Error())
			return
		}
		// generate secret
		key, err = xKey.GenerateSharedSecret(otherPub)
		if err != nil {
			log.Error("Cannot do the final key agreement: ", err.Error())
			return
		}
		goto startTransfer
	case "pbkdf2":
		// generate salt
		_, _ = rand.Read(salt)
		// now generate the key
		key = pbkdf2.Key([]byte(Password), salt, 1024*16, 32, sha1.New)
		// send salt to user
		err = conn.WriteMessage(websocket.BinaryMessage, salt)
		if err != nil {
			log.Error("Cannot send salt to client: ", err.Error())
			return
		}
	case "scrypt":
		// generate salt
		_, _ = rand.Read(salt)
		// send salt to user
		err = conn.WriteMessage(websocket.BinaryMessage, salt)
		if err != nil {
			log.Error("Cannot send salt to client: ", err.Error())
			return
		}
		// generate the key
		key, err = scrypt.Key([]byte(Password), salt, 1<<14, 8, 1, 32)
		if err != nil {
			log.Error("Cannot creat key from scrypt: ", err.Error())
			return
		}
	case "argon2":
		// it's better to use 16 byte salt for argon2
		salt = make([]byte, 16)
		_, _ = rand.Read(salt)
		// send salt to user
		err = conn.WriteMessage(websocket.BinaryMessage, salt)
		if err != nil {
			log.Error("Cannot send salt to client: ", err.Error())
			return
		}
		// generate the key
		key = argon2.IDKey([]byte(Password), salt, 10, 1<<14, 2, 32)
	}

	// save the data in map
	if KeyAgreement == "pbkdf2" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" {
		// we reuse salt; generate a random id for user
		salt = make([]byte, 8)
		_, _ = rand.Read(salt)
		salt[0] |= 128
		err = conn.WriteMessage(websocket.BinaryMessage, salt) // send the id to client
		if err != nil {
			log.Error("Cannot send id to client: ", err.Error())
			return
		}
		IdAndKeys.Set(string(salt), key) // save it
		log.WithFields(log.Fields{
			"address": conn.RemoteAddr(),
			"id":      base64.StdEncoding.EncodeToString(salt),
			"key":     base64.StdEncoding.EncodeToString(key),
		}).Trace("New handshake")
	}
	return // do not start coping

startTransfer:
	// dial the destination
	proxy, err := net.Dial("tcp", To)
	if err != nil {
		log.Error("Cannot dial ", To, ": ", err.Error())
		return
	}
	defer proxy.Close()

	log.Trace("Key is ", base64.StdEncoding.EncodeToString(key), " for ", conn.RemoteAddr())
	// start transfer
	var err2 error
	mu := sync.Mutex{} // this is used to sync the errors
	go func() {        // get the data from proxy; server -> client; These data must be encrypted
		mu.Lock()
		var nr, i int
		buf := make([]byte, BufferSize) // this is only used in reading from proxy
		if Encryption == "xor" {        // this is only for performance. Once for all define if you we are going to use AEAD interface or xor
			for {
				nr, err2 = proxy.Read(buf)
				if nr > 0 {
					for i = 0; i < nr; i++ { // encrypt
						buf[i] ^= key[i%32]
					}
					err2 = conn.WriteMessage(websocket.BinaryMessage, buf[:nr]) // send to client
				}
				if err2 != nil {
					if err2 == io.EOF {
						err2 = nil
					}
					return
				}
			}
		} else {
			// ready encryption stuff
			var c cipher.AEAD
			var cipherText []byte
			nonce := make([]byte, 12)
			if Encryption == "aes" {
				block, err := aes.NewCipher(key)
				if err != nil {
					return
				}
				c, err = cipher.NewGCM(block)
				if err != nil {
					return
				}
			} else { // chacha
				c, err = chacha20poly1305.New(key)
				if err != nil {
					return
				}
			}
			// start transfer
			for {
				nr, err2 = proxy.Read(buf)
				if nr > 0 {
					_, _ = rand.Read(nonce)
					cipherText = c.Seal(nil, nonce, buf[:nr], nil)                // encrypt data
					cipherText = append(nonce, cipherText...)                     // add nonce
					err2 = conn.WriteMessage(websocket.BinaryMessage, cipherText) // send to client
					if err2 != nil {
						break
					}
				}
				if err2 != nil {
					if err2 == io.EOF {
						err2 = nil
					}
					break
				}
			}
		}
		mu.Unlock()
	}()
	// client -> server ; must be decrypted
	if Encryption == "xor" {
		var message []byte
		var i, nr int
		for {
			_, message, err = conn.ReadMessage() // read the message
			if err != nil {
				break
			}
			nr = len(message)
			for i = 0; i < nr; i++ { // decrypt
				message[i] ^= key[i%32]
			}
			_, err = proxy.Write(message) // send to proxy
			if err != nil {
				break
			}
		}
	} else {
		var c cipher.AEAD
		var plainText []byte
		if Encryption == "aes" {
			block, err := aes.NewCipher(key)
			if err != nil {
				return
			}
			c, err = cipher.NewGCM(block)
			if err != nil {
				return
			}
		} else { // chacha
			c, err = chacha20poly1305.New(key)
			if err != nil {
				return
			}
		}
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}
			plainText, err = c.Open(nil, message[:12], message[12:], nil)
			if err != nil {
				log.Println(err)
				break
			}
			_, err = proxy.Write(plainText)
			if err != nil {
				break
			}
		}
	}
	mu.Lock() // wait until mutex is free; no need to unlock. It will be gone with GC
	if err != nil {
		log.Debug("Error on copy (server -> client): ", err.Error())
	}
	if err != nil {
		log.Debug("Error on copy (client -> server): ", err.Error())
	}
}

// listen for incoming connections in client to forward them
func WebsocketListenClient(serverUrl url.URL) error {
	log.Info("starting local TCP listener on ", InterfaceAddress+":"+Port)
	listener, err := net.Listen("tcp", InterfaceAddress+":"+Port) // listen on the port and interface for connections
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept() // accept incoming connections
		if err != nil {
			log.Error("Could not accept a connection from ", conn.RemoteAddr(), "; ", err.Error())
			continue
		}

		log.Debug("Accepting a connection from ", conn.RemoteAddr())
		go WebsocketHandleClientConnection(conn, serverUrl)
	}
}

func WebsocketHandleClientConnection(conn net.Conn, serverUrl url.URL) {
	// at first connect to server
	srv, _, err := dialer.Dial(serverUrl.String(), nil)
	if err != nil {
		log.Error("Cannot dial ", To, ": ", err.Error())
		return
	}
	defer srv.Close()

	var key []byte // is always 256 bit

	// this means that the key must be in the idAndKeys
	for item := range IdAndKeys.IterBuffered() {
		log.Trace(base64.StdEncoding.EncodeToString([]byte(item.Key)), " -> ", base64.StdEncoding.EncodeToString(item.Val.([]byte)))
		err = srv.WriteMessage(websocket.BinaryMessage, []byte(item.Key))
		if err != nil {
			log.Error("cannot send the id to server", err.Error())
			return
		}
		key = item.Val.([]byte)
	}

	// do the key agreement
	if KeyAgreement == "x25519" { // in theses methods we should get the RSA key and encrypt out password with it
		_, rsaPem, err := srv.ReadMessage() // read the RSA public key
		if err != nil {
			log.Error("Cannot get the public key of server: ", err.Error())
			return
		}
		pubKey, err := crypt.RSABytesToPublicKey(rsaPem) // pem to public key
		if err != nil {
			log.Error("Cannot convert public key of server: ", err.Error())
			return
		}

		// encrypt the password
		encryptedPass, err := crypt.RSAEncryptWithPublicKey([]byte(Password), pubKey)
		if err != nil {
			log.Error("Cannot convert public key of server: ", err.Error())
			return
		}
		err = srv.WriteMessage(websocket.BinaryMessage, encryptedPass)
		if err != nil {
			log.Error("Cannot send encrypted password to server: ", err.Error())
			return
		}
	}

	// get the key
	salt := make([]byte, 8)
	switch KeyAgreement {
	case "sha-256":
		key = []byte(Password) // that's it :D
	case "x25519":
		salt = make([]byte, 32) // salt here is public key of server
		// at first generate a x25519 key pair (server also creates one meanwhile)
		xKey, err := x25519.NewX25519()
		if err != nil {
			log.Error("Cannot generate X25519 key pair: ", err.Error())
			return
		}
		// read the server's public key
		_, salt, err = srv.ReadMessage()
		if err != nil {
			log.Error("Cannot get client's X25519 public key: ", err.Error())
			return
		}
		// send the public key to server
		err = srv.WriteMessage(websocket.BinaryMessage, xKey.PublicKey)
		if err != nil {
			log.Error("Cannot send public key to client: ", err.Error())
			return
		}
		// generate secret
		key, err = xKey.GenerateSharedSecret(salt)
		if err != nil {
			log.Error("Cannot do the final key agreement: ", err.Error())
			return
		}
	}

	log.Trace("Key is ", base64.StdEncoding.EncodeToString(key), " for ", srv.LocalAddr())

	// now start coping
	var err2 error
	mu := sync.Mutex{} // this is used to sync the errors
	go func() {
		mu.Lock()
		// server -> client ; must be decrypted
		var message []byte
		if Encryption == "xor" {
			var i int
			for {
				// get the message
				_, message, err2 = srv.ReadMessage()
				if err2 != nil {
					break
				}
				// decrypt the message
				for i = 0; i < len(message); i++ {
					message[i] ^= key[i%32]
				}
				// send message to proxy
				_, err2 = conn.Write(message)
				if err2 != nil {
					break
				}
			}
		} else {
			// ready decryption stuff
			var c cipher.AEAD
			var plainText []byte
			if Encryption == "aes" {
				block, err2 := aes.NewCipher(key)
				if err2 != nil {
					return
				}
				c, err2 = cipher.NewGCM(block)
				if err2 != nil {
					return
				}
			} else { // chacha
				c, err2 = chacha20poly1305.New(key)
				if err2 != nil {
					return
				}
			}
			for {
				// get the message
				_, message, err2 = srv.ReadMessage()
				if err2 != nil {
					break
				}
				// decrypt the message
				plainText, err2 = c.Open(nil, message[:12], message[12:], nil)
				if err2 != nil {
					log.Error("Error on decrypting data: ", err2.Error())
					srv.Close()
					conn.Close()
					return
				}
				_, err2 = conn.Write(plainText)
				if err2 != nil {
					break
				}
			}
		}
		mu.Unlock()
	}()

	// client -> server ; must be encrypted. Use default buffer size
	{
		buffer := make([]byte, BufferSize)
		var i, readCount int
		if Encryption == "xor" {
			for {
				readCount, err = conn.Read(buffer) // read the data from proxy
				if err != nil {
					if err == io.EOF {
						err = nil
					}
					break
				}
				for i = 0; i < readCount; i++ { // cipher with xor
					buffer[i] ^= key[i%32]
				}
				// send it to server
				err = srv.WriteMessage(websocket.BinaryMessage, buffer[:readCount])
				if err != nil {
					break
				}
			}
		} else {
			// setup encryption stuff
			var c cipher.AEAD
			var cipherText []byte
			nonce := make([]byte, 12)
			if Encryption == "aes" {
				block, err := aes.NewCipher(key)
				if err != nil {
					return
				}
				c, err = cipher.NewGCM(block)
				if err != nil {
					return
				}
			} else { // chacha
				c, err = chacha20poly1305.New(key)
				if err != nil {
					return
				}
			}
			for {
				readCount, err = conn.Read(buffer) // read the data from proxy
				if err != nil {
					if err == io.EOF {
						err = nil
					}
					break
				}
				_, _ = rand.Read(nonce)
				cipherText = c.Seal(nil, nonce, buffer[:readCount], nil) // encrypt data
				cipherText = append(nonce, cipherText...)                // add nonce
				// send it to server
				err = srv.WriteMessage(websocket.BinaryMessage, cipherText)
				if err != nil {
					break
				}
			}
		}
	}
	mu.Lock() // wait until mutex is free; no need to unlock. It will be gone with GC
	if err2 != nil {
		log.Debug("Error on copy (server -> client): ", err2.Error())
	}
	if err != nil {
		log.Debug("Error on copy (client -> server): ", err.Error())
	}
}
