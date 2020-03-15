package main

import (
	"SecureForwarder/crypt"
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/gorilla/websocket"
	"github.com/orcaman/concurrent-map"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var (
	upgrader  = websocket.Upgrader{}
	wsDialer  = websocket.Dialer{}
	tcpDialer = net.Dialer{}
)

var IdAndKeys cmap.ConcurrentMap

var (
	To               string // where the traffic should be forwarded. Server address in client and destination in server application
	Port             string // the port that the client or server listens on
	InterfaceAddress string // where should we bind the proxy?
	Password         string // the password of the user. Plaintext
	TransferType     string // how the data should be transferred; tcp,ws,wss
	Encryption       string // the encryption type; xor,aes,chacha
	KeyAgreement     string // key agreement algorithm
	BufferSize       int    // buffer size of the server. SERVER AND CLIENT SHOULD HAVE SAME VALUE ON TCP MODE
	Loglevel         string // how much logs should be shown to user
	CertPath         string // tls cert path; Used only with wss connections
	KeyPath          string // tls key path; Used only with wss connections
	ServerApp        bool   // is this running as server application
	TrustCert        bool   // trust unverified certs? (for wss only)
	Multiplex        bool   // shall we multiplex connections?
)

var (
	RSAPublicPem  []byte
	RSAPrivateKey *rsa.PrivateKey
)

// mux variables for websocket
const (
	muxSYC = byte(0) // hello
	muxFIN = byte(1) // close connection
	muxPSH = byte(2) // push data
)

const VERSION = "1.0.0 / Build 1"

func main() {
	IdAndKeys = cmap.New()
	logInit()

	if os.Getenv("SS_LOCAL_HOST") != "" { // check if the program is running as shadowsocks plugin
		var exists bool
		args := ParseShadowsocksOptions(os.Getenv("SS_PLUGIN_OPTIONS"))
		_, ServerApp = args["server"] // check if this is server application
		// check the password
		if Password, exists = args["password"]; !exists {
			log.Fatal("Password is not defined")
		}
		// parse transfer type
		if TransferType, exists = args["type"]; !exists {
			TransferType = "tcp"
		}
		// parse encryption type
		if Encryption, exists = args["encryption"]; !exists {
			Encryption = "chacha"
		}
		// parse key agreement
		if KeyAgreement, exists = args["agreement"]; !exists {
			KeyAgreement = "pbkdf2"
		}
		// buffer size key agreement
		if BufferSizeString, exists := args["buffer"]; !exists {
			BufferSize = 1024 * 32
		} else {
			BufferSizeI, err := strconv.Atoi(BufferSizeString)
			if err != nil {
				log.WithField("error", err.Error()).Fatal("Cannot parse BufferSize")
			}
			BufferSize = BufferSizeI
		}
		// parse loglevel
		if Loglevel, exists = args["loglevel"]; !exists {
			Loglevel = "info"
		}
		// parse multiplexing
		_, Multiplex = args["mux"]
		// parse IP and etc
		if ServerApp { // server mode
			if To, exists = args["host"]; exists {
				To += ":" + os.Getenv("SS_LOCAL_PORT")
			} else {
				To = os.Getenv("SS_LOCAL_HOST") + ":" + os.Getenv("SS_LOCAL_PORT")
			}
			InterfaceAddress = os.Getenv("SS_REMOTE_HOST")
			Port = os.Getenv("SS_REMOTE_PORT")
			// parse cert path
			if CertPath, exists = args["cert"]; !exists {
				CertPath = "cert.pem"
			}
			if KeyPath, exists = args["key"]; !exists {
				KeyPath = "cert.pem"
			}

			// start the server
			err := StartServer()
			if err != nil {
				log.Fatal(err)
			}
		} else { // client mode
			To = os.Getenv("SS_REMOTE_HOST") + ":" + os.Getenv("SS_REMOTE_PORT")
			InterfaceAddress = os.Getenv("SS_LOCAL_HOST")
			Port = os.Getenv("SS_LOCAL_PORT")
			// check if trust the certs
			_, TrustCert = args["trust"]

			// start the client
			err := StartClient()
			if err != nil {
				log.Fatal(err)
			}
		}

		return
	}

	app := &cli.App{
		Name:        "Secure Forwarder",
		Usage:       "Forward your encrypted packets",
		Version:     VERSION,
		Description: "Securely forwards your data over the internet.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "to",
				Usage:       "Where these packets should be forwarded?",
				Required:    true,
				Destination: &To,
			},
			&cli.StringFlag{
				Name:        "port",
				Usage:       "The port that the proxy should listen on",
				Required:    true,
				Destination: &Port,
			},
			&cli.StringFlag{
				Name:        "interface",
				Usage:       "The address that the proxy should listen on",
				Required:    false,
				DefaultText: "localhost on client and 0.0.0.0 on server",
				Destination: &InterfaceAddress,
			},
			&cli.StringFlag{
				Name:        "password",
				Aliases:     []string{"p"},
				Usage:       "The password of the proxy",
				Required:    true,
				Destination: &Password,
			},
			&cli.StringFlag{
				Name:        "encryption",
				Aliases:     []string{"e"},
				Usage:       "The encryption type: (xor,aes,chacha)",
				Required:    false,
				Value:       "chacha",
				Destination: &Encryption,
			},
			&cli.StringFlag{
				Name:        "type",
				Aliases:     []string{"t"},
				Usage:       "The forward type: (tcp,ws,wss)",
				Required:    false,
				Value:       "tcp",
				Destination: &TransferType,
			},
			&cli.StringFlag{
				Name:        "agreement",
				Usage:       "Key agreement type for connections. (sha-256,x25519,pbkdf2,scrypt,argon2)",
				Required:    false,
				Value:       "pbkdf2",
				Destination: &KeyAgreement,
			},
			&cli.IntFlag{
				Name:        "buffer",
				Usage:       "Buffer size if the proxy is running in TCP mode; SERVER AND CLIENT SHOULD HAVE SAME VALUE ON TCP MODE",
				Required:    false,
				Value:       1024 * 32,
				Destination: &BufferSize,
			},
			&cli.StringFlag{
				Name:        "loglevel",
				Usage:       "Log level (trace,debug,info,warn,error,fatal,panic)",
				Required:    false,
				Value:       "info",
				Destination: &Loglevel,
			},
			&cli.BoolFlag{
				Name:        "multiplex",
				Aliases:     []string{"m"},
				Usage:       "Use multiplex all connections into one connection",
				Required:    false,
				Value:       false,
				Destination: &Multiplex,
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "server",
				Aliases: []string{"s"},
				Flags: []cli.Flag{
					&cli.PathFlag{
						Name:        "cert",
						Usage:       "Certificate if you are using wss",
						Required:    false,
						Value:       "cert.pem",
						Destination: &CertPath,
					},
					&cli.PathFlag{
						Name:        "key",
						Usage:       "Key of certificate if you are using wss",
						Required:    false,
						Value:       "key.pem",
						Destination: &KeyPath,
					},
				},
				Usage: "run as server application",
				Action: func(c *cli.Context) error {
					return StartServer()
				},
			},
			{
				Name:    "client",
				Aliases: []string{"c"},
				Usage:   "run as client application",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:        "trust",
						Usage:       "Trust unverified certificates",
						Required:    false,
						Value:       false,
						Destination: &TrustCert,
					},
				},
				Action: func(c *cli.Context) error {
					return StartClient()
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

// start the server instance
func StartServer() error {
	ServerApp = true
	err := FixAndCheckArguments()
	if err != nil {
		return err
	}
	// log
	log.WithFields(log.Fields{
		"KeyAgreement": KeyAgreement,
		"TransferType": TransferType,
		"Encryption":   Encryption,
		"Buffer":       BufferSize,
	}).Debug()
	// start listening according to type of transfer type
	switch TransferType {
	case "tcp": // use raw tcp
		return TCPStartListen()
	case "ws": // use unencrypted websocket
		upgrader.ReadBufferSize = BufferSize + 28 // no need to add 28 but it's fine
		upgrader.WriteBufferSize = BufferSize + 28
		// create ws server
		if Multiplex {
			http.HandleFunc("/", WebsocketBaseMux)
		} else {
			http.HandleFunc("/", WebsocketBaseRaw)
		}
		log.Info("starting WS listener on ", InterfaceAddress+":"+Port)
		return http.ListenAndServe(InterfaceAddress+":"+Port, nil)
	case "wss": // use secure websocket
		upgrader.ReadBufferSize = BufferSize + 28 // no need to add 28 but it's fine
		upgrader.WriteBufferSize = BufferSize + 28
		// create ws server
		if Multiplex {
			http.HandleFunc("/", WebsocketBaseMux)
		} else {
			http.HandleFunc("/", WebsocketBaseRaw)
		}
		log.Info("starting WSS listener on ", InterfaceAddress+":"+Port)
		return http.ListenAndServeTLS(InterfaceAddress+":"+Port, CertPath, KeyPath, nil)
	}
	return nil
}

// start the client instance
func StartClient() error {
	ServerApp = false
	err := FixAndCheckArguments()
	if err != nil {
		return err
	}
	// log
	log.WithFields(log.Fields{
		"KeyAgreement": KeyAgreement,
		"TransferType": TransferType,
		"Encryption":   Encryption,
		"Buffer":       BufferSize,
	}).Debug()
	// start listening according to type of transfer type
	if TransferType == "tcp" { // use raw tcp
		// make sure we do not loopback connection on ss android
		tcpDialer.Control = protector
		// handle mux if needed
		if Multiplex {
			return TCPHandleForwardClientMux()
		}
		// before to start listening for connection do the handshake if needed
		if KeyAgreement == "pbkdf2" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" { // these algorithms need handshake
			err = func() error {
				id := make([]byte, 8)
				srv, err := tcpDialer.Dial("tcp", To) // connect to server
				if err != nil {
					log.Error("Cannot dial when client wanted to handshake")
					return err
				}
				defer srv.Close()
				_, err = srv.Write(id) // just inform the server that I want to do handshake; First bit is 0
				if err != nil {
					log.Error("Cannot send data to server in handshake")
					return err
				}

				// perform the rsa handshake if needed
				if KeyAgreement == "scrypt" || KeyAgreement == "argon2" { // in theses methods we should get the RSA key and encrypt out password with it
					rsaPem := make([]byte, 1024*4)     // 16384 bit RSA is 2880 bytes. Just make sure that there is enough buffer to read the key
					readCount, err := srv.Read(rsaPem) // read the RSA public key
					if err != nil {
						log.Error("Cannot get the public key of server: ", err.Error())
						return err
					}
					pubKey, err := crypt.RSABytesToPublicKey(rsaPem[:readCount]) // pem to public key
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
					_, err = srv.Write(encryptedPass)
					if err != nil {
						log.Error("Cannot send encrypted password to server: ", err.Error())
						return err
					}
				}

				// get the key
				salt := make([]byte, 8)
				var key []byte // is always 256 bit
				switch KeyAgreement {
				case "pbkdf2":
					// server sends a 8 byte salt to us
					_, err = srv.Read(salt)
					if err != nil {
						log.Error("Cannot read salt from server. Invalid password? : ", err.Error())
						return err
					}
					// generate shared key
					key = pbkdf2.Key([]byte(Password), salt, 1024*16, 32, sha1.New)
				case "scrypt":
					// server sends a 8 byte salt to us
					_, err = srv.Read(salt)
					if err != nil {
						log.Error("Cannot read salt from server. Invalid password? : ", err.Error())
						return err
					}
					// generate shared key
					key, err = scrypt.Key([]byte(Password), salt, 1<<14, 8, 1, 32)
				case "argon2":
					// server sends a 16 byte salt to us
					salt = make([]byte, 16)
					_, err = srv.Read(salt)
					if err != nil {
						log.Error("Cannot read salt from server. Invalid password? : ", err.Error())
						return err
					}
					// generate shared key
					key = argon2.IDKey([]byte(Password), salt, 10, 1<<14, 2, 32)
				}

				log.Trace("Key is ", base64.StdEncoding.EncodeToString(key))
				_, err = srv.Read(id)
				if err != nil {
					log.Error("Cannot get id from server")
					return err
				}
				log.Trace("Id is ", base64.StdEncoding.EncodeToString(id))
				IdAndKeys.Set(string(id), key)
				return nil
			}()
			if err != nil {
				return err
			}
		}
		// start listing
		return TCPStartListen()
	}
	// set websocket buffers
	wsDialer.WriteBufferSize = BufferSize + 28
	wsDialer.ReadBufferSize = BufferSize + 28
	{ // prevent loopback
		netDialer := &net.Dialer{Control: protector}
		wsDialer.NetDial = func(network, addr string) (net.Conn, error) {
			return netDialer.DialContext(context.Background(), network, addr)
		}
	}
	// at first check the certificate verification and create URL
	serverUrl := url.URL{Scheme: TransferType, Host: To, Path: "/"}
	if TrustCert {
		log.Debug("Trusting all certs")
		wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	// use mutex if needed
	if Multiplex {
		return WebsocketListenClientMux(serverUrl)
	}
	// before to start listening for connection do the handshake if needed
	if KeyAgreement == "pbkdf2" || KeyAgreement == "scrypt" || KeyAgreement == "argon2" { // these algorithms need handshake
		err = func() error {
			id := make([]byte, 8)
			srv, _, err := wsDialer.Dial(serverUrl.String(), nil)
			if err != nil {
				log.Error("Cannot dial when client wanted to handshake")
				return err
			}
			defer srv.Close()
			err = srv.WriteMessage(websocket.BinaryMessage, id) // just inform the server that I want to do handshake; First bit is 0
			if err != nil {
				log.Error("Cannot send data to server in handshake")
				return err
			}

			// perform the rsa handshake if needed
			if KeyAgreement == "scrypt" || KeyAgreement == "argon2" { // in theses methods we should get the RSA key and encrypt out password with it
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

			// get the key
			salt := make([]byte, 8)
			var key []byte // is always 256 bit
			switch KeyAgreement {
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
			_, id, err = srv.ReadMessage()
			if err != nil {
				log.Error("Cannot get id from server")
				return err
			}
			log.Trace("Id is ", base64.StdEncoding.EncodeToString(id))
			IdAndKeys.Set(string(id), key)
			return nil
		}()
		if err != nil {
			return err
		}
	}

	// now start listing for local connections and forward them
	return WebsocketListenClientRaw(serverUrl)
}

// check and fix arguments
func FixAndCheckArguments() error {
	// at first all of the methods must be in lowercase
	Encryption = strings.ToLower(Encryption)
	TransferType = strings.ToLower(TransferType)
	KeyAgreement = strings.ToLower(KeyAgreement)
	Loglevel = strings.ToLower(Loglevel)
	// set loglevel
	switch Loglevel {
	case "trace":
		log.Info("Log level set on trace.")
		log.SetLevel(log.TraceLevel)
	case "debug":
		log.Info("Log level set on debug.")
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	}
	// check encryption type
	if !StringArrayContains([]string{"xor", "aes", "chacha"}, Encryption) {
		return errors.New("undefined encryption type")
	}
	if !StringArrayContains([]string{"sha-256", "x25519", "pbkdf2", "scrypt", "argon2"}, KeyAgreement) {
		return errors.New("undefined key agreement method type")
	}
	if !StringArrayContains([]string{"tcp", "ws", "wss"}, TransferType) {
		return errors.New("undefined forward method type")
	}
	// fix interface
	if InterfaceAddress == "" {
		if ServerApp {
			InterfaceAddress = "0.0.0.0"
		} else {
			InterfaceAddress = "localhost"
		}
	}
	// generate RSA keys if needed
	if ServerApp && KeyAgreement != "sha-256" && KeyAgreement != "pbkdf2" {
		log.Info("Generating a RSA-2048 key pair")
		RSAPrivateKey = crypt.RSAGenerateKeyPair(2048)
		RSAPublicPem = crypt.RSAPublicKeyToBytes(&RSAPrivateKey.PublicKey)
		log.Info("Done generating a RSA-2048 key pair")
	}
	// hash the password if needed
	if KeyAgreement == "sha-256" {
		hashed := sha256.Sum256([]byte(Password))
		Password = string(hashed[:]) // you might think why this guy is converting a binary data to string? If I used []byte, when I would have used bytes.Equal that this function does in fact convert byte slices to string
		log.Trace("Key is ", base64.StdEncoding.EncodeToString(hashed[:]))
	}
	return nil
}

// checks if a string array contains an element
func StringArrayContains(array []string, toCheck string) bool {
	for _, v := range array {
		if v == toCheck {
			return true
		}
	}
	return false
}

// parse shadowsocks arguments
func ParseShadowsocksOptions(arg string) map[string]string {
	res := make(map[string]string)
	split := strings.Split(arg, ";") // at first split the args
	for _, v := range split {
		keyValue := strings.Split(v, "=")
		if len(keyValue) == 1 { // these are bool values
			res[keyValue[0]] = ""
		} else {
			res[keyValue[0]] = keyValue[1]
		}
	}
	return res
}
