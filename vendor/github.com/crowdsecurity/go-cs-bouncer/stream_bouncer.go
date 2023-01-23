package csbouncer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var TotalLAPIError prometheus.Counter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "lapi_requests_failures_total",
	Help: "The total number of failed calls to CrowdSec LAPI",
},
)

var TotalLAPICalls prometheus.Counter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "lapi_requests_total",
	Help: "The total number of calls to CrowdSec LAPI",
},
)

type StreamBouncer struct {
	APIKey             string `yaml:"api_key"`
	APIUrl             string `yaml:"api_url"`
	InsecureSkipVerify *bool  `yaml:"insecure_skip_verify"`
	CertPath           string `yaml:"cert_path"`
	KeyPath            string `yaml:"key_path"`
	CAPath             string `yaml:"ca_cert_path"`

	TickerInterval         string   `yaml:"update_frequency"`
	Scopes                 []string `yaml:"scopes"`
	ScenariosContaining    []string `yaml:"scenarios_containing"`
	ScenariosNotContaining []string `yaml:"scenarios_not_containing"`
	Origins                []string `yaml:"origins"`

	TickerIntervalDuration time.Duration
	Stream                 chan *models.DecisionsStreamResponse
	APIClient              *apiclient.ApiClient
	UserAgent              string
	Opts                   apiclient.DecisionsStreamOpts
}

// Config() fills the struct with configuration values from a file. It is not
// aware of .yaml.local files so it is recommended to use ConfigReader() instead
func (b *StreamBouncer) Config(configPath string) error {
	reader, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file '%s': %w", configPath, err)
	}

	return b.ConfigReader(reader)
}

func (b *StreamBouncer) ConfigReader(configReader io.Reader) error {
	content, err := io.ReadAll(configReader)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}
	err = yaml.Unmarshal(content, b)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	if b.Scopes != nil {
		b.Opts.Scopes = strings.Join(b.Scopes, ",")
	}

	if b.ScenariosContaining != nil {
		b.Opts.ScenariosContaining = strings.Join(b.ScenariosContaining, ",")
	}

	if b.ScenariosNotContaining != nil {
		b.Opts.ScenariosNotContaining = strings.Join(b.ScenariosNotContaining, ",")
	}

	if b.Origins != nil {
		b.Opts.Origins = strings.Join(b.Origins, ",")
	}

	if b.APIUrl == "" {
		return fmt.Errorf("config does not contain LAPI url")
	}
	if !strings.HasSuffix(b.APIUrl, "/") {
		b.APIUrl += "/"
	}
	if b.APIKey == "" && b.CertPath == "" && b.KeyPath == "" {
		return fmt.Errorf("config does not contain LAPI key or certificate")
	}

	return nil
}

func (b *StreamBouncer) Init() error {
	var (
		err                error
		apiURL             *url.URL
		client             *http.Client
		caCertPool         *x509.CertPool
		ok                 bool
		InsecureSkipVerify bool
	)

	b.Stream = make(chan *models.DecisionsStreamResponse)

	apiURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return fmt.Errorf("local API Url '%s': %w", b.APIUrl, err)
	}

	if b.InsecureSkipVerify == nil {
		InsecureSkipVerify = false
	} else {
		InsecureSkipVerify = *b.InsecureSkipVerify
	}

	if b.CAPath != "" {
		log.Infof("Using CA cert '%s'", b.CAPath)
		caCert, err := os.ReadFile(b.CAPath)
		if err != nil {
			return fmt.Errorf("unable to load CA certificate '%s': %w", b.CAPath, err)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	} else {
		caCertPool = nil
	}

	if b.APIKey != "" {
		log.Infof("Using API key auth")
		var transport *apiclient.APIKeyTransport
		if apiURL.Scheme == "https" {
			transport = &apiclient.APIKeyTransport{
				APIKey: b.APIKey,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:            caCertPool,
						InsecureSkipVerify: InsecureSkipVerify,
					},
				},
			}
		} else {
			transport = &apiclient.APIKeyTransport{
				APIKey: b.APIKey,
			}
		}
		client = transport.Client()
		ok = true
	}

	if b.CertPath != "" && b.KeyPath != "" {
		var certificate tls.Certificate

		log.Infof("Using cert auth with cert '%s' and key '%s'", b.CertPath, b.KeyPath)
		certificate, err = tls.LoadX509KeyPair(b.CertPath, b.KeyPath)
		if err != nil {
			return fmt.Errorf("unable to load certificate '%s' and key '%s': %w", b.CertPath, b.KeyPath, err)
		}

		client = &http.Client{}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{certificate},
				InsecureSkipVerify: InsecureSkipVerify,
			},
		}
		ok = true
	}

	if !ok {
		return errors.New("no API key nor certificate provided")
	}

	b.APIClient, err = apiclient.NewDefaultClient(apiURL, "v1", b.UserAgent, client)
	if err != nil {
		return fmt.Errorf("api client init: %w", err)
	}

	b.TickerIntervalDuration, err = time.ParseDuration(b.TickerInterval)
	if err != nil {
		return fmt.Errorf("unable to parse duration '%s': %w", b.TickerInterval, err)
	}
	return nil
}

func (b *StreamBouncer) Run() {
	ticker := time.NewTicker(b.TickerIntervalDuration)

	b.Opts.Startup = true

	getDecisionStream := func() (*models.DecisionsStreamResponse, *apiclient.Response, error) {
		data, resp, err := b.APIClient.Decisions.GetStream(context.Background(), b.Opts)
		TotalLAPICalls.Inc()
		if err != nil {
			TotalLAPIError.Inc()
		}
		return data, resp, err
	}

	data, resp, err := getDecisionStream()

	if resp != nil && resp.Response != nil {
		resp.Response.Body.Close()
	}

	if err != nil {
		log.Errorf(err.Error())
		return
	}

	b.Stream <- data
	b.Opts.Startup = false
	for range ticker.C {
		data, resp, err := getDecisionStream()
		if err != nil {
			if resp != nil && resp.Response != nil {
				resp.Response.Body.Close()
			}
			log.Errorf(err.Error())
			continue
		}
		if resp != nil && resp.Response != nil {
			resp.Response.Body.Close()
		}
		b.Stream <- data
	}
}
