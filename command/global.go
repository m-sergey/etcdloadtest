// Copyright 2017 Huawei Technoligies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package command

import (
	"log"
	"time"
	"errors"
	"crypto/tls"
	"strings"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"

	"github.com/spf13/cobra"

	"github.com/bgentry/speakeasy"
)

var (
	rounds                 int           // total number of rounds the operation needs to be performed
	totalClientConnections int           // total number of client connections to be made with server
	noOfPrefixes           int           // total number of prefixes which will be watched upon
	watchPerPrefix         int           // number of watchers per prefix
	reqRate                int           // put request per second
	totalKeys              int           // total number of keys for operation
	totalConcurrentOp      int           // total no of concurrent operations to be performed for load
	runningTime            time.Duration // time for which operation should be performed
	keyLength              int           // Total length of key
	valueLength            int           // Total length of value
	consistencyType        string        // consistency for read operation
)

type discoveryCfg struct {
	domain      string
	insecure    bool
	serviceName string
}

type secureCfg struct {
	cert   string
	key    string
	cacert string

	insecureTransport  bool
	insecureSkipVerify bool
}

type authCfg struct {
	username string
	password string
}

// GlobalFlags are flags that defined globally
// and are inherited to all sub-commands.
type GlobalFlags struct {
	Endpoints   		[]string
	DialTimeout 		time.Duration
	CaCert				string
	Key					string
	Cert				string
	InsecureTransport	bool
	User 				string
	Insecure			bool
	InsecureSkipVerify	bool
}

func keyAndCertFromCmd(cmd *cobra.Command) (cert, key, cacert string) {
	var err error
	if cert, err = cmd.Flags().GetString("cert"); err != nil {
		ExitWithError(ExitError, err)
	} else if cert == "" && cmd.Flags().Changed("cert") {
		ExitWithError(ExitError, errors.New("empty string is passed to --cert option"))
	}

	if key, err = cmd.Flags().GetString("key"); err != nil {
		ExitWithError(ExitError,  err)
	} else if key == "" && cmd.Flags().Changed("key") {
		ExitWithError(ExitError, errors.New("empty string is passed to --key option"))
	}

	if cacert, err = cmd.Flags().GetString("cacert"); err != nil {
		ExitWithError(ExitError, err)
	} else if cacert == "" && cmd.Flags().Changed("cacert") {
		ExitWithError(ExitError, errors.New("empty string is passed to --cacert option"))
	}

	return cert, key, cacert
}

func insecureTransportFromCmd(cmd *cobra.Command) bool {
	insecureTr, err := cmd.Flags().GetBool("insecure-transport")
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return insecureTr
}

func insecureSkipVerifyFromCmd(cmd *cobra.Command) bool {
	skipVerify, err := cmd.Flags().GetBool("insecure-skip-tls-verify")
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return skipVerify
}

func discoverySrvFromCmd(cmd *cobra.Command) string {
	domainStr, err := cmd.Flags().GetString("discovery-srv")
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return domainStr
}

func insecureDiscoveryFromCmd(cmd *cobra.Command) bool {
	discovery, err := cmd.Flags().GetBool("insecure-discovery")
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return discovery
}

func discoveryDNSClusterServiceNameFromCmd(cmd *cobra.Command) string {
	serviceNameStr, err := cmd.Flags().GetString("discovery-srv-name")
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return serviceNameStr
}

func discoveryCfgFromCmd(cmd *cobra.Command) *discoveryCfg {
	return &discoveryCfg{
		domain:      discoverySrvFromCmd(cmd),
		insecure:    insecureDiscoveryFromCmd(cmd),
		serviceName: discoveryDNSClusterServiceNameFromCmd(cmd),
	}
}

func secureCfgFromCmd(cmd *cobra.Command) *secureCfg {
	cert, key, cacert := keyAndCertFromCmd(cmd)
	insecureTr := insecureTransportFromCmd(cmd)
	skipVerify := insecureSkipVerifyFromCmd(cmd)
	discoveryCfg := discoveryCfgFromCmd(cmd)

	if discoveryCfg.insecure {
		discoveryCfg.domain = ""
	}

	return &secureCfg{
		cert:   cert,
		key:    key,
		cacert: cacert,

		insecureTransport:  insecureTr,
		insecureSkipVerify: skipVerify,
	}
}

func newClientCfg(endpoints []string, dialTimeout time.Duration, scfg *secureCfg, acfg *authCfg) (*clientv3.Config, error) {
	// set tls if any one tls option set
	var cfgtls *transport.TLSInfo
	tlsinfo := transport.TLSInfo{}
	if scfg.cert != "" {
		tlsinfo.CertFile = scfg.cert
		cfgtls = &tlsinfo
	}

	if scfg.key != "" {
		tlsinfo.KeyFile = scfg.key
		cfgtls = &tlsinfo
	}

	if scfg.cacert != "" {
		tlsinfo.CAFile = scfg.cacert
		cfgtls = &tlsinfo
	}

	cfg := &clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: dialTimeout,
	}
	if cfgtls != nil {
		clientTLS, err := cfgtls.ClientConfig()
		if err != nil {
			return nil, err
		}
		cfg.TLS = clientTLS
	}
	// if key/cert is not given but user wants secure connection, we
	// should still setup an empty tls configuration for gRPC to setup
	// secure connection.
	if cfg.TLS == nil && !scfg.insecureTransport {
		cfg.TLS = &tls.Config{}
	}

	// If the user wants to skip TLS verification then we should set
	// the InsecureSkipVerify flag in tls configuration.
	if scfg.insecureSkipVerify && cfg.TLS != nil {
		cfg.TLS.InsecureSkipVerify = true
	}

	if acfg != nil {
		cfg.Username = acfg.username
		cfg.Password = acfg.password
	}

	return cfg, nil
}

func authCfgFromCmd(cmd *cobra.Command) *authCfg {
	userFlag, err := cmd.Flags().GetString("user")
	if err != nil {
		ExitWithError(ExitBadArgs, err)
	}

	if userFlag == "" {
		return nil
	}

	var cfg authCfg

	splitted := strings.SplitN(userFlag, ":", 2)
	if len(splitted) < 2 {
		cfg.username = userFlag
		cfg.password, err = speakeasy.Ask("Password: ")
		if err != nil {
			ExitWithError(ExitError, err)
		}
	} else {
		cfg.username = splitted[0]
		cfg.password = splitted[1]
	}

	return &cfg
}

func newClient(endpoints []string, timeout time.Duration, scfg *secureCfg, acfg *authCfg) *clientv3.Client {
	cfg, err := newClientCfg(endpoints, timeout, scfg, acfg)
	if err != nil {
		ExitWithError(ExitBadArgs, err)
	}

	c, err := clientv3.New(*cfg)
	if err != nil {
		log.Fatal(err)
	}
	return c
}

func getClientConnections(cmd *cobra.Command, noOfConnections int) []*clientv3.Client {
	eps := endpointsFromFlag(cmd)
	dialTimeout := dialTimeoutFromCmd(cmd)
	clients := make([]*clientv3.Client, 0)
	totaleps := len(eps)
	sec := secureCfgFromCmd(cmd)
	auth := authCfgFromCmd(cmd)

	for i := 0; i < noOfConnections; i++ {
		c := newClient([]string{eps[i%totaleps]}, dialTimeout, sec, auth)
		clients = append(clients, c)
	}
	return clients
}

func endpointsFromFlag(cmd *cobra.Command) []string {
	endpoints, err := cmd.Flags().GetStringSlice("endpoints")
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return endpoints
}

func dialTimeoutFromCmd(cmd *cobra.Command) time.Duration {
	dialTimeout, err := cmd.Flags().GetDuration("dial-timeout")
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return dialTimeout
}

func getStringFlag(cmd *cobra.Command, flag string) string {
	value, err := cmd.Flags().GetString(flag)
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return value
}

func getBoolFlag(cmd *cobra.Command, flag string) bool {
	value, err := cmd.Flags().GetBool(flag)
	if err != nil {
		ExitWithError(ExitError, err)
	}
	return value
}
