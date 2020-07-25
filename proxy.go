package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tjmerritt/httpproxy/internal/config"

	"github.com/lithammer/shortuuid"
)

//type streamTransform func (req, upstreamReq *http.Request, out io.Writer, in io.Reader) error

var logDebug bool
var logAsync bool
var logLock sync.Mutex
var outLock sync.Mutex
var logs = make(map[string][]string)

func logPrintf(id, f string, values ...interface{}) {
	v := fmt.Sprintf(f, values...)
	if logAsync || id == "" {
		log.Printf("%s: %s", id, v)
		return
	}
	logLock.Lock()
	defer logLock.Unlock()
	if msgs, ok := logs[id]; ok {
		msgs = append(msgs, v)
		logs[id] = msgs
	} else {
		logs[id] = []string{v}
	}
}

func logDebugf(id, f string, values ...interface{}) {
	if logDebug {
		logPrintf(id, f, values...)
	}
}

func logComit(id string) {
	logLock.Lock()
	msgs := logs[id]
	delete(logs, id)
	logLock.Unlock()
	outLock.Lock()
	defer outLock.Unlock()

	for _, msg := range msgs {
		log.Printf("%s: %s", id, msg)
	}
}

func addCookie(id string, h http.Header, cookie *http.Cookie) {
	h.Add("Cookie", cookie.String())
	logDebugf(id, "Cookie+: %s: %+v\n", cookie.Name, cookie)
}

func transformRequest(id string, origin, target *url.URL, req *http.Request) {
	logDebugf(id, "Request: %v\n", req)
	for key, values := range req.Header {
		for _, value := range values {
			logDebugf(id, "Header: %s: %+v\n", key, value)
		}
	}
	for _, cookie := range req.Cookies() {
		logDebugf(id, "Cookie: %s: %+v\n", cookie.Name, cookie)
	}
	if referer, ok := req.Header["Referer"]; ok && len(referer) == 1 {
		orig := origin.Hostname()
		ref := referer[0]
		i := strings.Index(ref, orig)
		if i >= 0 {
			l := len(orig)
			newReferer := ref[0:i] + target.Hostname() + ref[i+l:]
			req.Header.Set("Referer", newReferer)
			logDebugf(id, "New Referer: %s\n", newReferer)
		}
	}
	if req.URL.Path == "/" {
		addCookie(id, req.Header, &http.Cookie{Name: "TroopMasterWebSiteID", Value: "202340"})
	}
	//req.Header.Add("X-Forwarded-Host", req.Host)
	//req.Header.Add("X-Origin-Host", target.Host)
	req.URL.Scheme = target.Scheme
	host := target.Hostname()
	port := target.Port()
	logDebugf(id, "target: host %s port %s\n", host, port)
	if port == "" {
		switch target.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
		logDebugf(id, "target: host %s default port %s\n", host, port)
	}
	req.URL.Host = target.Host
	req.Host = net.JoinHostPort(host, port)
	logDebugf(id, "request.URL: %v\n", req.URL)
	logDebugf(id, "request.Host: %s\n", req.Host)
}

func transformResponse(id string, origin, target *url.URL, resp *http.Response) error {
	req := resp.Request
	logPrintf(id, "%s %s %s %d %s\n", req.URL.Scheme, req.Host, req.Method, resp.StatusCode, req.URL.Path)
	logDebugf(id, "Response: %v\n", resp)
	for _, cookie := range resp.Cookies() {
		logDebugf(id, "\tCookie: %s\n", cookie)
	}
	if resp.StatusCode == 302 {
		location := ""
		if len(resp.Header["Location"]) > 0 {
			location = resp.Header["Location"][0]
		}
		logDebugf(id, "Location: %s\n", location)
		tgt := target.Hostname()
		i := strings.Index(location, tgt)
		if i >= 0 {
			l := len(tgt)
			orig := origin.Hostname()
			newLocation := location[0:i] + orig + location[i+l:]
			resp.Header.Set("Location", newLocation)
			logDebugf(id, "New Location: %s\n", newLocation)
		}
	}
	return nil
}

func makeMux(proxy, upstream, redirOrigPath, redirTargetPath string) *http.ServeMux {
	origin, err := url.Parse(proxy)
	if err != nil {
		panic(err)
	}
	target, err := url.Parse(upstream)
	if err != nil {
		panic(err)
	}
	logDebugf("", "origin %v target %v\n", origin, target)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("handler panic: %v\n", err)
			}
		}()
		if r.URL.Path == redirOrigPath {
			http.Redirect(w, r, proxy+redirTargetPath, 302)
			return
		}

		id := shortuuid.New()
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				transformRequest(id, origin, target, req)
			},
			ModifyResponse: func(resp *http.Response) error {
				return transformResponse(id, origin, target, resp)
			},
		}
		proxy.ServeHTTP(w, r)
		logComit(id)
	})

	return mux
}

func startHTTPServer(addr, proxy, upstream, redirOrigPath, redirTargetPath string) *http.Server {
	logDebugf("", "startHTTPServer: addr %s proxy %s upstream %s redirPath %s redirTarget %s\n", addr, proxy, upstream, redirOrigPath, redirTargetPath)
	
	srv := &http.Server{
		Addr:    addr,
		Handler: makeMux(proxy, upstream, redirOrigPath, redirTargetPath),
	}
	go func() {
		log.Fatal(srv.ListenAndServe())
	}()
	return srv
}

func startHTTPSServer(addr, proxy, upstream, redirOrigPath, redirTargetPath, cert, key string) *http.Server {
	logDebugf("", "startHTTPSServer: addr %s proxy %s upstream %s redirPath %s redirTarget %s\n", addr, proxy, upstream, redirOrigPath, redirTargetPath)
	mux := makeMux(proxy, upstream, redirOrigPath, redirTargetPath)
	tlsMux := http.NewServeMux()
	tlsMux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		//		w.Header().Add("Strict-Transport-Security", "max-age=300; includeSubDomains")
		mux.ServeHTTP(w, req)
	})
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      tlsMux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	go func() {
		log.Fatal(srv.ListenAndServeTLS(cert, key))
	}()

	return srv
}

type Server struct {
	port int
	server *http.Server

}

type Site struct {
	domain string
	servers []*Server
}

func buildServer(domain string, serviceConfig *config.Server) (*Server, error) {
	if (len(serviceConfig.Backends) != 1) {
		return nil, fmt.Errorf("No backends for domain %s, service %s", domain, serviceConfig.Name)
	}

	server := &Server{}
	backend := serviceConfig.Backends[0].URL

	redirOrigPath := ""
	redirTargetPath := ""
	
	if (len(serviceConfig.Redirects) == 1) {
		redir := &serviceConfig.Redirects[0]
		redirOrigPath = redir.Path
		redirTargetPath = redir.Target
	}

	cert := serviceConfig.TLS.Certificate
	privKey := serviceConfig.TLS.PrivateKey

	if cert == "" && privKey == "" {
		server.server = startHTTPServer(serviceConfig.Addr, "http://"+domain, backend, redirOrigPath, redirTargetPath)
	} else {
		server.server = startHTTPSServer(serviceConfig.Addr, "http://"+domain, backend, redirOrigPath, redirTargetPath, cert, privKey)
	}
	return nil, nil
}

func buildSite(siteConfig *config.Site) (*Site, error) {
	domain := siteConfig.Domain
	servers := []*Server{}

	for i := range siteConfig.Services {
		serviceConfig := &siteConfig.Services[i]
		server, err := buildServer(domain, serviceConfig)
		if err != nil {
			return nil, err
		}
		servers = append(servers, server)
	}

	return &Site{
		domain: domain,
		servers: servers,
	}, nil
}

func buildSites(siteConfigs []config.Site) ([]*Site, error) {
	sites := []*Site{}

	for i := range siteConfigs {
		siteConfig := &siteConfigs[i]
		site, err := buildSite(siteConfig)
		if err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}

	return sites, nil
}

func shutdownSites(ctx context.Context, sites []*Site) error {
	var err2 error
	for _, site := range sites {
		for _, server := range site.servers {
			if err := server.server.Shutdown(ctx); err != nil {
				log.Printf("HTTP Server Shutdown Failed:%+v", err)
				if err2 == nil {
					err2 = err
				}
			}
		}
	}
	return err2
}

func main() {
	var configFile string

	flag.BoolVar(&logDebug, "debug", false, "Write debug logs")
	flag.BoolVar(&logAsync, "async", false, "Write logs asynchronously")
	flag.StringVar(&configFile, "config", "config.yaml", "configuration file name")
	flag.Parse()

	var configData config.Config

	if configFile != "" {
		if err := config.Read(configFile, &configData); err != nil {
			log.Printf("Error reading config file: %v\n", err)
		}
	}

	sites, err := buildSites(configData.Sites)
	if err != nil {
		log.Fatalf("HTTP Server Setup Failed:%+v", err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-done

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer func() {
		cancel()
	}()

	if err := shutdownSites(ctx, sites); err != nil {
		log.Fatalf("Error shuting down: %+v", err)
	}

	log.Print("Server Exited Properly")
}
