package config

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/go-yaml/yaml"
)

type Config struct {
	Servers []Server
	Backends []Backend
}

type Server struct {
	Name string
	Addr string
	Domains []Domain		// Domains also have paths, if they don't match then Server paths
	Paths []Path			// here are used.
}

type Backend struct {
	Name    string
	URL     string
}

type Domain struct {
	Name string
	TLS TLS
	Paths []Path
}

type TLS struct {
	Certificate string
	PrivateKey  string
}

// Path matching is done with the RE in Match, if Match is empty then is defaults the prefix Name
// If you want to only match a single path you need to use Match with just the path
type Path struct {
	Name string
	Also []string
	Match string		// if not set, defaults to "${Name}.*"
	Backend string
	Cookies []KVUpdate
	Headers []KVUpdate
	Redirect string
	Static string
}

type KVUpdate struct {
	Name string
	Match string
	Value string
	Replace string
}

/*
type Site struct {
	Domain   string
	Services []Service
}

type Service struct {
	Name      string
	Addr      string
	TLS       TLS
	Backends  []Backend
	Redirects []Redirect
}

type TLS struct {
	Certificate string
	PrivateKey  string
}

type Backend struct {
	Name    string
	URL     string
	Forward []string
}

type Redirect struct {
	Name   string
	Path   string
	Target string
}
*/

func Read(filename string, config interface{}) error {
	cfgFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer cfgFile.Close()
	b, err := ioutil.ReadAll(cfgFile)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(b, config)
	if err != nil {
		return err
	}
	s, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	log.Printf("Config:\n%s\n", string(s))
	return nil
}
