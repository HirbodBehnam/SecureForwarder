// this file contains all of the functions for raw tcp forward mode
package main

import (
	"SecureForwarder/crypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"github.com/HirbodBehnam/EasyX25519"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"io"
	"net"
	"sync"
)

// stating listing for connections to send them to client or server
func TCPStartListen() error {
	log.Info("starting TCP listener on ", InterfaceAddress+":"+Port)
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
		conn.RemoteAddr().Network()

		log.Debug("Accepting a connection from ", conn.RemoteAddr())
		if ServerApp {
			go TCPHandleForwardServer(conn)
		} else {
			go TCPHandleForwardClient(conn)
		}
	}
}

// do the key agreement and handshake and at last, start coping
func TCPHandleForwardServer(conn net.Conn) { // forward all connections
	defer conn.Close()
	var err error
	salt := make([]byte, 8)
	var key []byte // is always 256 bit

	// check the id for these algorithms
	if KeyAgreement == "pbkdf2" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" { // check the id map
		_, err = conn.Read(salt) // we temporary use salt
		if err != nil {
			log.Error("Cannot read id from client: ", err.Error())
			return
		}
		// check if this a handshake packet or client is using an id; Handshake packet starts with 0 in binary. However id always starts with 1
		if salt[0]&128 == 128 { // 128 = 10000000 in binary; 1 means id; Check the id
			if k, exists := IdAndKeys.Get(string(salt)); exists {
				key = k.([]byte) // key is always a byte array
				goto startTransfer
			}
		}
		// otherwise just continue to handshake
	}

	// perform rsa handshake
	if KeyAgreement == "x25519" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" {
		_, err = conn.Write(RSAPublicPem) // on client we use big buffer (8*1024) because in future I might add something to change the key size
		if err != nil {
			log.Error("Cannot write to client: ", err.Error())
			return
		}
		{ // read the client's response that must be RSA encrypted password
			tBuf := make([]byte, 8*1024)
			readC, err := conn.Read(tBuf)
			if err != nil {
				log.Error("Cannot write to client: ", err.Error())
				return
			}
			// try to decrypt the password
			decrypted, err := crypt.RSADecryptWithPrivateKey(tBuf[:readC], RSAPrivateKey)
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
		_, err = conn.Write(xKey.PublicKey)
		if err != nil {
			log.Error("Cannot send public key to client: ", err.Error())
			return
		}
		// get the public key of the user
		otherPub := make([]byte, 32) // key is always 32 byte
		_, err = conn.Read(otherPub)
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
		_, err = conn.Write(salt)
		if err != nil {
			log.Error("Cannot send salt to client: ", err.Error())
			return
		}
	case "scrypt":
		// generate salt
		_, _ = rand.Read(salt)
		// send salt to user
		_, err = conn.Write(salt)
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
		_, err = conn.Write(salt)
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
		_, err = conn.Write(salt) // send the id to client
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
	go func() {
		mu.Lock()
		err2 = TCPCopyConnectionDecrypt(conn, proxy, key) // client -> server ; must be decrypted. Use larger buffer size (same size for xor, larger for xor and +12 bytes for chacha and aes)
		mu.Unlock()
	}()
	err = TCPCopyConnectionEncrypt(proxy, conn, key) // server -> client ; must be encrypted. Use default buffer size
	mu.Lock()                                        // wait until mutex is free; no need to unlock. It will be gone with GC
	if err != nil {
		log.Debug("Error on copy (server -> client): ", err.Error())
	}
	if err != nil {
		log.Debug("Error on copy (client -> server): ", err.Error())
	}
}

// do the key agreement with server and start sending
func TCPHandleForwardClient(conn net.Conn) {
	// at first connect to server
	srv, err := net.Dial("tcp", To)
	if err != nil {
		log.Error("Cannot dial ", To, ": ", err.Error())
		return
	}
	defer srv.Close()

	var key []byte // is always 256 bit

	// this means that the key must be in the idAndKeys
	for item := range IdAndKeys.IterBuffered() {
		log.Trace(base64.StdEncoding.EncodeToString([]byte(item.Key)), " -> ", base64.StdEncoding.EncodeToString(item.Val.([]byte)))
		_, err = srv.Write([]byte(item.Key))
		if err != nil {
			log.Error("cannot send the id to server", err.Error())
			return
		}
		key = item.Val.([]byte)
	}

	// do the key agreement
	if KeyAgreement == "x25519" { // in theses methods we should get the RSA key and encrypt out password with it
		rsaPem := make([]byte, 1024*4)     // 16384 bit RSA is 2880 bytes. Just make sure that there is enough buffer to read the key
		readCount, err := srv.Read(rsaPem) // read the RSA public key
		if err != nil {
			log.Error("Cannot get the public key of server: ", err.Error())
			return
		}
		pubKey, err := crypt.RSABytesToPublicKey(rsaPem[:readCount]) // pem to public key
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
		_, err = srv.Write(encryptedPass)
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
		// read the servers public key
		_, err = srv.Read(salt)
		if err != nil {
			log.Error("Cannot get client's X25519 public key: ", err.Error())
			return
		}
		// send the public key to server
		_, err = srv.Write(xKey.PublicKey)
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
		err2 = TCPCopyConnectionDecrypt(srv, conn, key) // server -> client ; must be decrypted. Use larger buffer size (same size for xor, larger for xor and +12 bytes for chacha and aes)
		mu.Unlock()
	}()
	err = TCPCopyConnectionEncrypt(conn, srv, key) // client -> server ; must be encrypted. Use default buffer size
	mu.Lock()                                      // wait until mutex is free; no need to unlock. It will be gone with GC
	if err2 != nil {
		log.Debug("Error on copy (server -> client): ", err2.Error())
	}
	if err != nil {
		log.Debug("Error on copy (client -> server): ", err.Error())
	}
}

// this generally spicy io.copy
// starts coping a connections data to another
// uses key for encryption
// all of the packets will be encrypted before forwarding
// data will be read with normal buffer size
func TCPCopyConnectionEncrypt(src, dst net.Conn, key []byte) (err error) {
	var er, ew error
	var nr, nw, i int
	buf := make([]byte, BufferSize)
	if Encryption == "xor" { // this is only for performance. Once for all define if you we are going to use AEAD interface or xor
		for {
			nr, er = src.Read(buf)
			if nr > 0 {
				for i = 0; i < nr; i++ { // encrypt
					buf[i] ^= key[i%32]
				}
				nw, ew = dst.Write(buf[0:nr])
				if ew != nil {
					err = ew
					break
				}
				if nr != nw {
					err = io.ErrShortWrite
					break
				}
			}
			if er != nil {
				if er != io.EOF {
					err = er
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
				return err
			}
			c, err = cipher.NewGCM(block)
			if err != nil {
				return err
			}
		} else { // chacha
			c, err = chacha20poly1305.New(key)
			if err != nil {
				return err
			}
		}

		// read,generate nonce ,encrypt and send data
		for {
			nr, er = src.Read(buf)
			if nr > 0 {
				_, _ = rand.Read(nonce)
				cipherText = c.Seal(nil, nonce, buf[:nr], nil)
				cipherText = append(nonce, cipherText...) // add nonce
				_, ew = dst.Write(cipherText)
				if ew != nil {
					err = ew
					break
				}
			}
			if er != nil {
				if er != io.EOF {
					err = er
				}
				break
			}
		}
	}
	return err
}

// this generally spicy io.copy
// starts coping a connections data to another
// uses key for decryption
// all of the packets will be decrypted before forwarding
// data will be read with a larger buffer size in chacha and aes to include tag and nonce. Then data is decrypted
func TCPCopyConnectionDecrypt(src, dst net.Conn, key []byte) (err error) {
	var er, ew error
	var nr, nw, i, bufferSize int
	bufferSize = BufferSize
	if Encryption != "xor" {
		bufferSize += 28 // nonce + tag size: 12 + 16 = 28
	}
	buf := make([]byte, bufferSize)
	if Encryption == "xor" { // this is only for performance. Once for all define if you we are going to use AEAD interface or xor
		for {
			nr, er = src.Read(buf)
			if nr > 0 {
				for i = 0; i < nr; i++ { // encrypt
					buf[i] ^= key[i%32]
				}
				nw, ew = dst.Write(buf[0:nr])
				if ew != nil {
					err = ew
					break
				}
				if nr != nw {
					err = io.ErrShortWrite
					break
				}
			}
			if er != nil {
				if er != io.EOF {
					err = er
				}
				break
			}
		}
	} else {
		// ready encryption stuff
		var c cipher.AEAD
		var plainText []byte
		if Encryption == "aes" {
			block, err := aes.NewCipher(key)
			if err != nil {
				return err
			}
			c, err = cipher.NewGCM(block)
			if err != nil {
				return err
			}
		} else { // chacha
			c, err = chacha20poly1305.New(key)
			if err != nil {
				return err
			}
		}

		// read,generate nonce ,encrypt and send data
		for {
			nr, er = src.Read(buf)
			if nr > 0 {
				plainText, err = c.Open(nil, buf[:12], buf[12:nr], nil)
				if err != nil {
					log.Error("Error on decrypting data: ", err.Error())
					src.Close()
					dst.Close()
					return err
				}
				_, ew = dst.Write(plainText)
				if ew != nil {
					err = ew
					break
				}
			}
			if er != nil {
				if er != io.EOF {
					err = er
				}
				break
			}
		}
	}
	return err
}
