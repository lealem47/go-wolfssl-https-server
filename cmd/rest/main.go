package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	wolfSSL "github.com/wolfssl/go-wolfssl"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const defaultPort = "8443"

type wolfSSLListener struct {
	listener net.Listener
	ctx      *wolfSSL.WOLFSSL_CTX
}

// Accept waits for and returns the next connection to the listener.
func (cl *wolfSSLListener) Accept() (net.Conn, error) {
	conn, err := cl.listener.Accept()
	if err != nil {
		return nil, err
	}
	fmt.Println("Accepted new connection from:", conn.RemoteAddr())

	ssl := wolfSSL.WolfSSL_new(cl.ctx)
	if ssl == nil {
		fmt.Println("WolfSSL_new Failed")
		os.Exit(1)
	}

	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		panic(err)
	}
	fd := file.Fd()
	wolfSSL.WolfSSL_set_fd(ssl, int(fd))

	ret := wolfSSL.WolfSSL_accept(ssl)
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		fmt.Println("WolfSSL_accept error ", ret)
	} else {
		fmt.Println("Client Successfully Connected!")
	}

	return &wolfSSLConn{
		conn: conn,
		ssl:  ssl,
	}, nil
}

// Close closes the listener, making it stop accepting new connections.
func (cl *wolfSSLListener) Close() error {
	fmt.Println("Closing listener...")
	return cl.listener.Close()
}

// Addr returns the listener's network address.
func (cl *wolfSSLListener) Addr() net.Addr {
	return cl.listener.Addr()
}

type wolfSSLConn struct {
	conn   net.Conn
	ssl    *wolfSSL.WOLFSSL
	buffer bytes.Buffer
	mu     sync.Mutex
	closed bool
}

func (w *wolfSSLConn) Read(b []byte) (int, error) {
	log.Infof("Calling read: %d", len(b))

	ret := wolfSSL.WolfSSL_read(w.ssl, b, uintptr(len(b)))
	if ret < 0 {
		errCode := wolfSSL.WolfSSL_get_error(w.ssl, int(ret))
		return 0, fmt.Errorf("read error: %d", errCode)
	}

	log.Infof("Read bytes: %s", string(b[:ret]))
	return int(ret), nil
}

func (w *wolfSSLConn) Write(b []byte) (int, error) {
	log.Infof("Calling write: %d", len(b))

	sz := uintptr(len(b))

	ret := wolfSSL.WolfSSL_write(w.ssl, b, sz)
	if ret < 0 {
		errCode := wolfSSL.WolfSSL_get_error(w.ssl, int(ret))
		return 0, fmt.Errorf("write error: %d", errCode)
	}

	return int(ret), nil
}

func (w *wolfSSLConn) Close() error {
	log.Infof("Closing connection")

	wolfSSL.WolfSSL_shutdown(w.ssl)
	wolfSSL.WolfSSL_free(w.ssl)
	return w.conn.Close()
}

func (w *wolfSSLConn) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *wolfSSLConn) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *wolfSSLConn) SetDeadline(t time.Time) error {
	return w.conn.SetDeadline(t)
}

func (w *wolfSSLConn) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *wolfSSLConn) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

// Handler for generating and base64 encoding 5KB of random data
func randomDataHandler(w http.ResponseWriter, r *http.Request) {
	// Get the "size" query parameter from the request
	sizeParam := r.URL.Query().Get("size")
	size := 500000 // default size

	// If the "size" parameter is provided, convert it to an integer
	if sizeParam != "" {
		parsedSize, err := strconv.Atoi(sizeParam)
		if err != nil || parsedSize <= 0 {
			http.Error(w, "Invalid size parameter", http.StatusBadRequest)
			return
		}
		size = parsedSize
	}

	// Generate random data of the specified size
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		http.Error(w, "Could not generate random data", http.StatusInternalServerError)
		return
	}

	// Base64 encode the random data
	encodedData := base64.StdEncoding.EncodeToString(data)

	// Set content type and write the base64 encoded data
	w.Header().Set("Content-Type", "application/base64")
	w.Write([]byte(encodedData))
}

func main() {
	port := defaultPort

	// Set logging level
	log.SetLevel(log.InfoLevel)

	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})

	// Set up the HTTP server and routes
	http.HandleFunc("/", randomDataHandler)

	CERT_FILE := "./certs/server-cert.pem"
	KEY_FILE := "./certs/server-key.pem"

	/* Initialize wolfSSL */
	wolfSSL.WolfSSL_Init()

	/* Create WOLFSSL_CTX with tlsv12 */
	ctx := wolfSSL.WolfSSL_CTX_new(wolfSSL.WolfTLSv1_2_server_method())
	if ctx == nil {
		fmt.Println(" WolfSSL_CTX_new Failed")
		os.Exit(1)
	}

	/* Load server certificates into WOLFSSL_CTX */
	ret := wolfSSL.WolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, wolfSSL.SSL_FILETYPE_PEM)
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		fmt.Println("Error: WolfSSL_CTX_use_certificate Failed")
		os.Exit(1)
	}

	/* Load server key into WOLFSSL_CTX */
	ret = wolfSSL.WolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, wolfSSL.SSL_FILETYPE_PEM)
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		fmt.Println("Error: WolfSSL_CTX_use_PrivateKey Failed")
		os.Exit(1)
	}

	baseListener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Error starting listener:", err)
		return
	}
	defer baseListener.Close()

	wolfSSLListener := &wolfSSLListener{
		listener: baseListener,
		ctx:      ctx,
	}

	log.Printf("Server listening on https://localhost:%s", port)
	err = http.Serve(wolfSSLListener, nil)
	if err != nil {
		fmt.Println("Error starting HTTP server:", err)
	}
}
