package main

import (
	"github.com/tjmerritt/httpproxy/internal/config"
	"github.com/tjmerritt/httpproxy/internal/sni"
)

func serverPlan(cfg *config.Config) (*Plan, error) {
	return nil, nil
}

type Plan struct {
	addr string
	certs []sni.Certificate
	hosts []HostPlan
}

type HostPlan struct {
	hostname string
	//...
}
