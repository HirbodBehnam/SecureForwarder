package main

import (
	"SecureForwarder/crypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
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
	"strings"
	"sync"
)

// all clients are redirected here
func WebsocketBaseRaw(w http.ResponseWriter, r *http.Request) {
	// at first accept the websocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Cannot upgrade: ", err.Error())
		return
	}
	defer log.WithField("client", conn.RemoteAddr()).Debug("Closed connection")
	defer conn.Close()
	log.WithField("from", r.RemoteAddr).Debug("New connection")

	// do the handshake just like tcp
	salt := make([]byte, 8)
	var key []byte // is always 256 bit

	// check the id for these algorithms
	if KeyAgreement == "pbkdf2" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" {
		_, idStart, err := conn.ReadMessage() // read the id
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot read id from client")
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
			log.WithField("error", err.Error()).Error("Cannot write public key to client")
			return
		}
		{ // read the client's response that must be RSA encrypted password
			_, userPass, err := conn.ReadMessage()
			if err != nil {
				log.WithField("error", err.Error()).Error("Cannot read encrypted password from client")
				return
			}
			// try to decrypt the password
			decrypted, err := crypt.RSADecryptWithPrivateKey(userPass, RSAPrivateKey)
			if err != nil {
				log.WithFields(log.Fields{
					"from":  conn.RemoteAddr(),
					"error": err.Error(),
				}).Error("Invalid handshake")
				return
			}
			// check if the password was correct
			if string(decrypted) != Password {
				log.WithField("from", conn.RemoteAddr()).Error("Invalid password")
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
			log.WithField("error", err.Error()).Error("Cannot generate X25519 key pair")
			return
		}
		// send the public key to client
		err = conn.WriteMessage(websocket.BinaryMessage, xKey.PublicKey)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send public key to client")
			return
		}
		// get the public key of the user
		_, otherPub, err := conn.ReadMessage()
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot get client's X25519 public key")
			return
		}
		// generate secret
		key, err = xKey.GenerateSharedSecret(otherPub)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot do the final key agreement")
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
			log.WithField("error", err.Error()).Error("Cannot send salt to client")
			return
		}
	case "scrypt":
		// generate salt
		_, _ = rand.Read(salt)
		// send salt to user
		err = conn.WriteMessage(websocket.BinaryMessage, salt)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send salt to client")
			return
		}
		// generate the key
		key, err = scrypt.Key([]byte(Password), salt, 1<<14, 8, 1, 32)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot creat key from scrypt")
			return
		}
	case "argon2":
		// it's better to use 16 byte salt for argon2
		salt = make([]byte, 16)
		_, _ = rand.Read(salt)
		// send salt to user
		err = conn.WriteMessage(websocket.BinaryMessage, salt)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send salt to client")
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
			log.WithField("error", err.Error()).Error("Cannot send id to client")
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

	log.WithFields(log.Fields{
		"key":    base64.StdEncoding.EncodeToString(key),
		"client": conn.RemoteAddr(),
	}).Trace("Starting to proxy")

	// start transfer
	var err2 error
	done := make(chan bool, 1)
	go func() { // get the data from proxy; server -> client; These data must be encrypted
		defer close(done)
		defer conn.Close()
		defer proxy.Close()
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
				}
				if err2 != nil {
					if err2 == io.EOF {
						err2 = nil
					}
					break
				}
			}
		}
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
				log.WithFields(log.Fields{
					"src":   proxy.RemoteAddr(),
					"dest":  conn.RemoteAddr(),
					"error": err2.Error(),
				}).Error("Error on decrypting data")
				break
			}
			_, err = proxy.Write(plainText)
			if err != nil {
				break
			}
		}
	}

	proxy.Close()
	conn.Close()
	select {
	case <-done: // wait until it's over
	}

	if err2 != nil && !strings.Contains(err2.Error(), "use of closed network connection") {
		log.WithField("error", err2.Error()).Debug("Error on copy (server -> client)")
	}
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.WithField("error", err.Error()).Debug("Error on copy (client -> server)")
	}
}

func WebsocketBaseMux(w http.ResponseWriter, r *http.Request) {
	// at first accept the websocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Cannot upgrade: ", err.Error())
		return
	}
	defer log.WithField("client", conn.RemoteAddr()).Debug("Closed connection")
	defer conn.Close()
	log.WithField("from", r.RemoteAddr).Debug("New connection")

	salt := make([]byte, 8)
	var key []byte // is always 256 bit

	// do the handshake
	// perform rsa handshake
	if KeyAgreement == "x25519" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" {
		err = conn.WriteMessage(websocket.TextMessage, RSAPublicPem) // on client we use big buffer (8*1024) because in future I might add something to change the key size
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot write public key to client")
			return
		}
		{ // read the client's response that must be RSA encrypted password
			_, tBuf, err := conn.ReadMessage()
			if err != nil {
				log.WithField("error", err.Error()).Error("Cannot read clients response on RSA handshake")
				return
			}
			// try to decrypt the password
			decrypted, err := crypt.RSADecryptWithPrivateKey(tBuf, RSAPrivateKey)
			if err != nil {
				log.WithFields(log.Fields{
					"from":  conn.RemoteAddr(),
					"error": err.Error(),
				}).Error("Invalid handshake")
				return
			}
			// check if the password was correct
			if string(decrypted) != Password {
				log.WithField("from", conn.RemoteAddr()).Error("Invalid password")
				return
			}
		}
	}

	switch KeyAgreement {
	case "sha-256":
		key = []byte(Password) // that's it :D
	case "x25519": // this type is little different
		// at first generate a x25519 key pair (client also creates one meanwhile)
		xKey, err := x25519.NewX25519()
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot generate X25519 key pair")
			return
		}
		// send the public key to client
		err = conn.WriteMessage(websocket.BinaryMessage, xKey.PublicKey)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send public key to client")
			return
		}
		// get the public key of the user
		otherPub := make([]byte, 32) // key is always 32 byte
		err = conn.WriteMessage(websocket.BinaryMessage, otherPub)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot get client's X25519 public key")
			return
		}
		// generate secret
		key, err = xKey.GenerateSharedSecret(otherPub)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot do the final key agreement")
			return
		}
	case "pbkdf2":
		// generate salt
		_, _ = rand.Read(salt)
		// now generate the key
		key = pbkdf2.Key([]byte(Password), salt, 1024*16, 32, sha1.New)
		// send salt to user
		err = conn.WriteMessage(websocket.BinaryMessage, salt)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send salt to client")
			return
		}
	case "scrypt":
		// generate salt
		_, _ = rand.Read(salt)
		// send salt to user
		err = conn.WriteMessage(websocket.BinaryMessage, salt)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send salt to client")
			return
		}
		// generate the key
		key, err = scrypt.Key([]byte(Password), salt, 1<<14, 8, 1, 32)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot create key from scrypt")
			return
		}
	case "argon2":
		// it's better to use 16 byte salt for argon2
		salt = make([]byte, 16)
		_, _ = rand.Read(salt)
		// send salt to user
		err = conn.WriteMessage(websocket.BinaryMessage, salt)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send salt to client")
			return
		}
		// generate the key
		key = argon2.IDKey([]byte(Password), salt, 10, 1<<14, 2, 32)
	}

	log.Trace("Key is ", base64.StdEncoding.EncodeToString(key))

	// now start the mux server and listen to connections
	// packets are like this: 1byte cmd + 2byte id
	lastIndex := uint16(0)
	connectionMap := make(map[uint16]*net.Conn)
	mutex := sync.Mutex{}

	// define server -> client function
	ServerToClient := func(myIndex uint16) {
		proxy := connectionMap[myIndex]
		indexByte := make([]byte, 2)
		binary.LittleEndian.PutUint16(indexByte, myIndex)
		muxPacket := []byte{muxPSH, indexByte[0], indexByte[1]}
		defer func() {
			log.WithField("id", myIndex).Debug("sending muxFin")
			mutex.Lock()
			_ = conn.WriteMessage(websocket.BinaryMessage, []byte{muxFIN, indexByte[0], indexByte[1]})
			mutex.Unlock()
		}()
		var nr, i int
		var innerError error
		buf := make([]byte, BufferSize) // this is only used in reading from proxy
		if Encryption == "xor" {        // this is only for performance. Once for all define if you we are going to use AEAD interface or xor
			for {
				nr, innerError = (*proxy).Read(buf) // read from proxy
				if nr > 0 {
					for i = 0; i < nr; i++ { // encrypt
						buf[i] ^= key[i%32]
					}
					// add mux
					buf = append(muxPacket, buf...)
					mutex.Lock()
					innerError = conn.WriteMessage(websocket.BinaryMessage, buf[:nr+3]) // send to client
					mutex.Unlock()
				}
				if innerError != nil {
					if innerError == io.EOF {
						innerError = nil
					}
					break
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
			var finalPacket []byte
			for {
				nr, innerError = (*proxy).Read(buf)
				if nr > 0 {
					_, _ = rand.Read(nonce)
					cipherText = c.Seal(nil, nonce, buf[:nr], nil)   // encrypt data
					finalPacket = make([]byte, len(cipherText)+3+12) // add nonce and mux
					copy(finalPacket, muxPacket)
					copy(finalPacket[3:], nonce)
					copy(finalPacket[3+12:], cipherText)
					mutex.Lock()
					innerError = conn.WriteMessage(websocket.BinaryMessage, finalPacket) // send to client
					mutex.Unlock()
				}
				if innerError != nil {
					if innerError == io.EOF {
						innerError = nil
					}
					break
				}
			}
		}
	}

	// start transfer
	//go ServerToClient(0)

	// client -> server ; must be decrypted
	var connId uint16
	if Encryption == "xor" {
		var message []byte
		var i, nr int
		for {
			_, message, err = conn.ReadMessage() // read the message
			if err != nil {
				break
			}
			// check the mux options : byte: cmd, uint16: connection id
			switch message[0] {
			case muxSYC: // new connection
				lastIndex++ // last index will increase no matter if the connection is ok or not
				// dial a new connection and save it
				log.WithField("index", lastIndex).Trace("new mux session")
				newProxy, err := net.Dial("tcp", To)
				if err != nil {
					log.Error("Cannot dial ", To, ": ", err.Error())
					continue
				}
				connectionMap[lastIndex] = &newProxy
				// start a listener for this proxy
				go ServerToClient(lastIndex)
				continue
			case muxFIN: // close connection
				connId = binary.LittleEndian.Uint16(message[1:]) // 3 to n bytes are ignored
				(*connectionMap[connId]).Close()
				log.WithField("id", connId).Println("got muxFin")
				continue
			case muxPSH: // push data
				connId = binary.LittleEndian.Uint16(message[1:]) // 3 to n bytes are ignored
				// just continue in loop
			}

			message = message[3:]
			nr = len(message)
			for i = 0; i < nr; i++ { // decrypt
				message[i] ^= key[i%32]
			}

			_, err = (*connectionMap[connId]).Write(message) // send to proxy
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

			// check mux
			switch message[0] {
			case muxSYC: // new connection
				lastIndex++ // last index will increase no matter if the connection is ok or not
				// dial a new connection and save it
				log.WithField("index", lastIndex).Trace("new mux session")
				newProxy, err := net.Dial("tcp", To)
				if err != nil {
					log.Error("Cannot dial ", To, ": ", err.Error())
					continue
				}
				connectionMap[lastIndex] = &newProxy
				// start a listener for this proxy
				go ServerToClient(lastIndex)
				continue
			case muxFIN: // close connection
				connId = binary.LittleEndian.Uint16(message[1:]) // 3 to n bytes are ignored
				(*connectionMap[connId]).Close()
				log.WithField("id", connId).Debug("got muxFin")
				continue
			case muxPSH: // push data
				connId = binary.LittleEndian.Uint16(message[1:]) // 3 to n bytes are ignored
				// just continue in loop
			}

			message = message[3:]
			plainText, err = c.Open(nil, message[:12], message[12:], nil)
			if err != nil {
				log.WithFields(log.Fields{
					"src":   conn.RemoteAddr(),
					"dest":  (*connectionMap[connId]).RemoteAddr(),
					"error": err.Error(),
				}).Error("Error on decrypting data")
				break
			}
			_, err = (*connectionMap[connId]).Write(plainText)
			if err != nil {
				break
			}
		}
	}

	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.WithField("error", err.Error()).Debug("Error on copy (client -> server)")
	}
}

// listen for incoming connections in client to forward them
func WebsocketListenClientRaw(serverUrl url.URL) error {
	log.Info("starting local TCP listener on ", InterfaceAddress+":"+Port)
	listener, err := net.Listen("tcp", InterfaceAddress+":"+Port) // listen on the port and interface for connections
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept() // accept incoming connections
		if err != nil {
			log.WithFields(log.Fields{
				"from":  conn.RemoteAddr(),
				"error": err.Error(),
			}).Error("Could not accept an incoming connection")
			continue
		}

		log.WithField("from", conn.RemoteAddr()).Debug("Accepting a connection")
		go WebsocketHandleClientConnection(conn, serverUrl)
	}
}

// forwards the connections
func WebsocketHandleClientConnection(conn net.Conn, serverUrl url.URL) {
	// at first connect to server
	srv, _, err := wsDialer.Dial(serverUrl.String(), nil)
	if err != nil {
		log.Error("Cannot dial ", To, ": ", err.Error())
		return
	}
	defer log.WithField("client", conn.RemoteAddr()).Debug("Closed connection")
	defer srv.Close()

	var key []byte // is always 256 bit

	// this means that the key must be in the idAndKeys
	for item := range IdAndKeys.IterBuffered() {
		log.Trace(base64.StdEncoding.EncodeToString([]byte(item.Key)), " -> ", base64.StdEncoding.EncodeToString(item.Val.([]byte)))
		err = srv.WriteMessage(websocket.BinaryMessage, []byte(item.Key))
		if err != nil {
			log.WithField("error", err.Error()).Error("cannot send the id to server")
			return
		}
		key = item.Val.([]byte)
	}

	// do the key agreement
	if KeyAgreement == "x25519" { // in theses methods we should get the RSA key and encrypt out password with it
		_, rsaPem, err := srv.ReadMessage() // read the RSA public key
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot get the public key of server")
			return
		}
		pubKey, err := crypt.RSABytesToPublicKey(rsaPem) // pem to public key
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot parse public key of server")
			return
		}

		// encrypt the password
		encryptedPass, err := crypt.RSAEncryptWithPublicKey([]byte(Password), pubKey)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot convert public key of server")
			return
		}
		err = srv.WriteMessage(websocket.BinaryMessage, encryptedPass)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send encrypted password to server")
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
			log.WithField("error", err.Error()).Error("Cannot generate X25519 key pair")
			return
		}
		// read the server's public key
		_, salt, err = srv.ReadMessage()
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot get server's X25519 public key")
			return
		}
		// send the public key to server
		err = srv.WriteMessage(websocket.BinaryMessage, xKey.PublicKey)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send public key to server")
			return
		}
		// generate secret
		key, err = xKey.GenerateSharedSecret(salt)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot do the final key agreement")
			return
		}
	}

	log.Trace("Key is ", base64.StdEncoding.EncodeToString(key), " for ", srv.LocalAddr())

	// now start coping
	var err2 error
	done := make(chan bool, 1)
	go func() {
		defer close(done)
		defer conn.Close()
		defer srv.Close()
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
					log.WithFields(log.Fields{
						"src":   srv.RemoteAddr(),
						"dest":  conn.RemoteAddr(),
						"error": err2.Error(),
					}).Error("Error on decrypting data")
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

	conn.Close()
	srv.Close()
	select {
	case <-done: // wait until it's over
	}

	if err2 != nil && !strings.Contains(err2.Error(), "use of closed network connection") {
		log.WithField("error", err2.Error()).Debug("Error on copy (server -> client)")
	}
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.WithField("error", err.Error()).Debug("Error on copy (client -> server)")
	}
}

func WebsocketListenClientMux(serverUrl url.URL) error {
	// at first connect to server
	srv, _, err := wsDialer.Dial(serverUrl.String(), nil)
	if err != nil {
		log.Error("Cannot dial ", To, ": ", err.Error())
		return err
	}
	defer srv.Close()

	var key []byte // is always 256 bit
	salt := make([]byte, 8)

	// perform the rsa handshake if needed
	if KeyAgreement == "scrypt" || KeyAgreement == "argon2" || KeyAgreement == "x25519" { // in theses methods we should get the RSA key and encrypt out password with it
		_, rsaPem, err := srv.ReadMessage() // read the RSA public key
		if err != nil {
			log.Error("Cannot get the public key of server: ", err.Error())
			return err
		}
		pubKey, err := crypt.RSABytesToPublicKey(rsaPem) // pem to public key
		if err != nil {
			log.Error("Cannot convert public key of server: ", err.Error())
			return err
		}

		// encrypt the password
		encryptedPass, err := crypt.RSAEncryptWithPublicKey([]byte(Password), pubKey)
		if err != nil {
			log.Error("Cannot convert public key of server: ", err.Error())
			return err
		}
		err = srv.WriteMessage(websocket.BinaryMessage, encryptedPass)
		if err != nil {
			log.Error("Cannot send encrypted password to server: ", err.Error())
			return err
		}
	}

	switch KeyAgreement {
	case "sha-256":
		key = []byte(Password) // that's it :D
	case "x25519":
		salt = make([]byte, 32) // salt here is public key of server
		// at first generate a x25519 key pair (server also creates one meanwhile)
		xKey, err := x25519.NewX25519()
		if err != nil {
			log.WithField("error", err.Error()).Error("cannot generate X25519 key pair")
			return err
		}
		// read the servers public key
		_, salt, err = srv.ReadMessage()
		if err != nil {
			log.WithField("error", err.Error()).Error("cannot get server's X25519 public key")
			return err
		}
		// send the public key to server
		err = srv.WriteMessage(websocket.BinaryMessage, xKey.PublicKey)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot send public key to server")
			return err
		}
		// generate secret
		key, err = xKey.GenerateSharedSecret(salt)
		if err != nil {
			log.WithField("error", err.Error()).Error("Cannot do the final key agreement")
			return err
		}
	case "pbkdf2":
		// server sends a 8 byte salt to us
		_, salt, err = srv.ReadMessage()
		if err != nil {
			log.Error("Cannot read salt from server. Invalid password? : ", err.Error())
			return err
		}
		// generate shared key
		key = pbkdf2.Key([]byte(Password), salt, 1024*16, 32, sha1.New)
	case "scrypt":
		// server sends a 8 byte salt to us
		_, salt, err = srv.ReadMessage()
		if err != nil {
			log.Error("Cannot read salt from server. Invalid password? : ", err.Error())
			return err
		}
		// generate shared key
		key, err = scrypt.Key([]byte(Password), salt, 1<<14, 8, 1, 32)
	case "argon2":
		// server sends a 16 byte salt to us
		_, salt, err = srv.ReadMessage()
		if err != nil {
			log.Error("Cannot read salt from server. Invalid password? : ", err.Error())
			return err
		}
		// generate shared key
		key = argon2.IDKey([]byte(Password), salt, 10, 1<<14, 2, 32)
	}
	log.Trace("Key is ", base64.StdEncoding.EncodeToString(key))

	log.Info("starting local TCP listener on ", InterfaceAddress+":"+Port)
	listener, err := net.Listen("tcp", InterfaceAddress+":"+Port) // listen on the port and interface for connections
	if err != nil {
		return err
	}

	lastIndex := uint16(0)
	connectionMap := make(map[uint16]*net.Conn)
	mutex := sync.Mutex{}
	// listen for incoming packets; server -> client must be decrypted
	go func() {
		defer log.Fatal("Main reader loop exited")
		var connId uint16
		if Encryption == "xor" {
			var message []byte
			var i, nr int
			for {
				_, message, err = srv.ReadMessage() // read the message
				if err != nil {
					break
				}
				// check the mux options : byte: cmd, uint16: connection id
				switch message[0] {
				case muxFIN: // close connection
					connId = binary.LittleEndian.Uint16(message[1:]) // 3 to n bytes are ignored
					(*connectionMap[connId]).Close()
					log.WithField("id", connId).Debug("got muxFin")
					continue
				case muxPSH: // push data
					connId = binary.LittleEndian.Uint16(message[1:]) // 3 to n bytes are ignored
					// just continue in loop
				}

				message = message[3:]
				nr = len(message)
				for i = 0; i < nr; i++ { // decrypt
					message[i] ^= key[i%32]
				}

				_, err = (*connectionMap[connId]).Write(message) // send to proxy
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
				_, message, err := srv.ReadMessage()
				if err != nil {
					log.Error("Error on read message: ", err.Error())
					break
				}

				// check mux
				switch message[0] {
				case muxFIN: // close connection
					connId = binary.LittleEndian.Uint16(message[1:]) // 3 to n bytes are ignored
					(*connectionMap[connId]).Close()
					log.WithField("id", connId).Debug("got muxFin")
					continue
				case muxPSH: // push data
					connId = binary.LittleEndian.Uint16(message[1:]) // 3 to n bytes are ignored
					// just continue in loop
				}
				message = message[3:]
				plainText, err = c.Open(nil, message[:12], message[12:], nil)
				if err != nil {
					log.WithFields(log.Fields{
						"src":   srv.RemoteAddr(),
						"dest":  (*connectionMap[connId]).RemoteAddr(),
						"error": err.Error(),
					}).Error("Error on decrypting data")
					break
				}
				_, err = (*connectionMap[connId]).Write(plainText)
				if err != nil {
					// shall i send muxFIN?
					log.WithFields(log.Fields{
						"src":   srv.RemoteAddr(),
						"dest":  (*connectionMap[connId]).RemoteAddr(),
						"error": err.Error(),
					}).Warn("error on writing data")
				}
			}
		}
	}()

	for {
		lastIndex++
		local, err := listener.Accept() // accept incoming connections
		if err != nil {
			log.WithFields(log.Fields{
				"from":  local.RemoteAddr(),
				"error": err.Error(),
			}).Error("Could not accept an incoming connection")
			continue
		}
		log.WithFields(log.Fields{
			"from": local.RemoteAddr(),
			"id":   lastIndex,
		}).Debug("accepting a connection")

		// client -> server; Must be encrypted
		go func(conn net.Conn, index uint16) {
			byteIndex := make([]byte, 2)
			binary.LittleEndian.PutUint16(byteIndex, index)
			pushPacket := []byte{muxPSH, byteIndex[0], byteIndex[1]}
			var innerError error
			defer log.WithField("conn", conn.RemoteAddr()).Debug("closing local connection")
			defer conn.Close()
			defer func() {
				log.WithFields(log.Fields{
					"err": innerError,
					"id":  index,
				}).Debug("sending muxFin")
				mutex.Lock()
				_ = srv.WriteMessage(websocket.BinaryMessage, []byte{muxFIN, byteIndex[0], byteIndex[1]}) // terminate mux
				mutex.Unlock()
			}()
			// send muxSYC
			connectionMap[index] = &conn
			mutex.Lock()
			innerError = srv.WriteMessage(websocket.BinaryMessage, []byte{muxSYC})
			mutex.Unlock()
			if innerError != nil {
				log.Error("cannot send mux hello to server")
				return
			}
			// start transferring data
			var nr, i int
			buf := make([]byte, BufferSize) // this is only used in reading from proxy
			if Encryption == "xor" {        // this is only for performance. Once for all define if you we are going to use AEAD interface or xor
				for {
					nr, innerError = conn.Read(buf) // read from proxy
					if nr > 0 {
						for i = 0; i < nr; i++ { // encrypt
							buf[i] ^= key[i%32]
						}
						// add mux
						buf = append(pushPacket, buf...)
						mutex.Lock()
						innerError = srv.WriteMessage(websocket.BinaryMessage, buf[:nr+3]) // send to client
						mutex.Unlock()
					}
					if innerError != nil {
						if innerError == io.EOF {
							innerError = nil
						}
						break
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
				var finalPacket []byte
				for {
					nr, innerError = conn.Read(buf)
					if nr > 0 {
						_, _ = rand.Read(nonce)
						cipherText = c.Seal(nil, nonce, buf[:nr], nil)   // encrypt data
						finalPacket = make([]byte, len(cipherText)+3+12) // add nonce and mux
						copy(finalPacket, pushPacket)
						copy(finalPacket[3:], nonce)
						copy(finalPacket[3+12:], cipherText)
						mutex.Lock()
						innerError = srv.WriteMessage(websocket.BinaryMessage, finalPacket) // send to client
						mutex.Unlock()
					}
					if innerError != nil {
						if innerError == io.EOF {
							innerError = nil
						}
						break
					}
				}
			}
		}(local, lastIndex)
	}
}
