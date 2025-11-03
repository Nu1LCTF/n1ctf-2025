package httpd

import (
	"kvstore/store"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Store interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Status() store.StoreStatus
}

type Service struct {
	addr  string
	store Store
}

func New(addr string, store Store) *Service {
	return &Service{
		addr:  addr,
		store: store,
	}
}

func (s *Service) Start() {
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Set("store", s.store)
		c.Next()
	})

	r.GET("/key/:key", GetKey)
	r.POST("/key/:key", SetKey)
	r.GET("/status", Status)

	go func() {
		log.Fatal(r.Run(s.addr))
	}()
}

func GetKey(c *gin.Context) {
	kvstore := c.MustGet("store").(Store)

	k := c.Param("key")
	if k == "" {
		c.AbortWithStatus(http.StatusBadRequest)
	}

	v, err := kvstore.Get(k)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	c.String(http.StatusOK, v)
}

func SetKey(c *gin.Context) {
	kvstore := c.MustGet("store").(Store)

	k := c.Param("key")
	if k == "" {
		c.AbortWithStatus(http.StatusBadRequest)
	}

	v, err := c.GetRawData()
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	if vv, _ := kvstore.Get(k); vv != "" {
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	if err = kvstore.Set(k, string(v)); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	c.Status(http.StatusCreated)
}

func Status(c *gin.Context) {
	kvstore := c.MustGet("store").(Store)
	status := kvstore.Status()
	c.JSON(http.StatusOK, status)
}
