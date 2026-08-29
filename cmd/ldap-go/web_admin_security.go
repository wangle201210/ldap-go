package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

func validateWebAdminTransport(
	listenAddress,
	certificateFile,
	privateKeyFile string,
) error {
	if strings.TrimSpace(listenAddress) == "" {
		return errors.New("web-admin -listen requires a non-empty TCP address")
	}
	if (certificateFile == "") != (privateKeyFile == "") {
		return errors.New("web-admin HTTPS requires both -tls-cert and -tls-key")
	}
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return fmt.Errorf("web-admin listen address: %w", err)
	}
	if certificateFile != "" {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New(
			"web-admin plaintext HTTP is restricted to loopback; configure -tls-cert and -tls-key for other listeners",
		)
	}
	return nil
}

func webAdminListenIsLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateWebAdminPublicURL(raw string, secure, loopback bool) error {
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("web-admin -public-url must contain only scheme and host")
	}
	if secure && parsed.Scheme != "https" {
		return errors.New("web-admin -public-url must use https")
	}
	if !secure && parsed.Scheme == "https" && !loopback {
		return errors.New("web-admin HTTPS proxy termination is allowed only on a loopback listener")
	}
	return nil
}
