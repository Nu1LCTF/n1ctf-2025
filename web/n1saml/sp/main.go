package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
)

type DynamicSP struct {
	endpoint string
	samlSP   *samlsp.Middleware
}

func (mw *DynamicSP) fetchMetadata() (*saml.EntityDescriptor, error) {
	metadataURL, err := url.Parse(mw.endpoint)
	if err != nil {
		log.Println("failed to parse metadata URL:", err)
		return nil, err
	}

	metadataURL.Path = "/key/metadata"
	resp, err := http.Get(metadataURL.String())
	if err != nil {
		log.Println("failed to fetch metadata:", err)
		return nil, err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("failed to read metadata response body:", err)
		return nil, err
	}

	dec, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		log.Println("failed to decode metadata:", err)
		return nil, err
	}

	metadata, err := samlsp.ParseMetadata(dec)
	if err != nil {
		log.Println("failed to parse metadata:", err)
		return nil, err
	}

	return metadata, nil
}

func (mw *DynamicSP) Serve(c *gin.Context) {
	if c.Request.URL.Path == mw.samlSP.ServiceProvider.AcsURL.Path {
		metadata, err := mw.fetchMetadata()
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to fetch IdP metadata")
			return
		}
		mw.samlSP.ServiceProvider.IDPMetadata = metadata
	}
	mw.samlSP.ServeHTTP(c.Writer, c.Request)
}

func (mw *DynamicSP) RequireAccount(h gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		metadata, err := mw.fetchMetadata()
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to fetch IdP metadata")
			return
		}
		mw.samlSP.ServiceProvider.IDPMetadata = metadata

		session, err := mw.samlSP.Session.GetSession(c.Request)
		if session != nil {
			c.Request = c.Request.WithContext(samlsp.ContextWithSession(c.Request.Context(), session))
			h(c)
			return
		}
		if errors.Is(err, samlsp.ErrNoSession) {
			mw.samlSP.HandleStartAuthFlow(c.Writer, c.Request)
			return
		}

		mw.samlSP.OnError(c.Writer, c.Request, err)
	}
}

func Index(c *gin.Context) {
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, `<h1>It works!</h1>`)
}

func Whoami(c *gin.Context) {
	c.Header("Content-Type", "text/plain")

	session := samlsp.SessionFromContext(c.Request.Context())
	if session == nil {
		c.String(http.StatusForbidden, "not signed in")
		return
	}

	sessionWithAttrs, ok := session.(samlsp.SessionWithAttributes)
	if !ok {
		c.String(http.StatusInternalServerError, "no attributes available")
		return
	}

	attributes := sessionWithAttrs.GetAttributes()
	uid := attributes.Get("uid")
	mail := attributes.Get("mail")

	if uid == "Administrator" && mail == "admin@nu1l.com" {
		c.String(http.StatusOK, "Welcome, Administrator! Here is your flag: %s", readFlag())
	} else {
		c.String(http.StatusOK, "You are not Administrator.")
	}
}

func readFlag() string {
	b, _ := os.ReadFile("/flag")
	return string(b)
}

var (
	addr     string
	spURL    string
	cert     string
	key      string
	endpoint string
)

func init() {
	flag.StringVar(&addr, "addr", "", "HTTP bind address")
	flag.StringVar(&spURL, "url", "", "Service Provider URL")
	flag.StringVar(&cert, "cert", "", "Path to the certificate")
	flag.StringVar(&key, "key", "", "Path to the private key")
	flag.StringVar(&endpoint, "endpoint", "", "KV Store endpoint")
}

func main() {
	flag.Parse()

	if addr == "" || spURL == "" || cert == "" || key == "" || endpoint == "" {
		flag.Usage()
		return
	}

	rootURL, err := url.Parse(spURL)
	if err != nil {
		log.Fatal("failed to parse SP URL:", err)
	}

	keyPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Fatal("failed to load key pair:", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatal("failed to parse certificate:", err)
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		SignRequest: true,
	})
	if err != nil {
		log.Fatal("failed to create SAML SP middleware:", err)
	}

	mw := &DynamicSP{
		samlSP:   samlSP,
		endpoint: endpoint,
	}

	r := gin.Default()

	r.GET("/", Index)
	r.GET("/whoami", mw.RequireAccount(Whoami))
	r.Any("/saml/*any", func(c *gin.Context) {
		mw.Serve(c)
	})

	log.Fatal(r.Run(addr))
}
