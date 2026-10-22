package atrust

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"

	"github.com/mythologyli/zju-connect/client"
)

func tlsConfig(config *tls.Config, keyLogWriter io.Writer) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	if keyLogWriter != nil {
		config.KeyLogWriter = keyLogWriter
	}
	return config
}

// tunnelTLSConfig mirrors the official client's standard TLS transport while
// retaining the caller's verification policy.
func tunnelTLSConfig(base *tls.Config, keyLogWriter io.Writer) *tls.Config {
	cfg := tlsConfig(base, keyLogWriter)
	cfg.SessionTicketsDisabled = true
	return cfg
}

func dialTLSContext(ctx context.Context, dialer client.UnderlayDialer, network, address string, config *tls.Config) (*tls.Conn, error) {
	if dialer == nil {
		return nil, errors.New("underlay dialer is required")
	}
	rawConn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	if config.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr == nil {
			config.ServerName = host
		}
	}
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
