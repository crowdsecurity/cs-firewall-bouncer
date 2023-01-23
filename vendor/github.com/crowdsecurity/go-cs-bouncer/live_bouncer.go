package csbouncer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type LiveBouncer struct {
	APIKey             string `yaml:"api_key"`
	APIUrl             string `yaml:"api_url"`
	InsecureSkipVerify *bool  `yaml:"insecure_skip_verify"`
	CertPath           string `yaml:"cert_path"`
	KeyPath            string `yaml:"key_path"`
	CAPath             string `yaml:"ca_path"`

	APIClient *apiclient.ApiClient
	UserAgent string
}

// Config() fills the struct with configuration values from a file. It is not
// aware of .yaml.local files so it is recommended to use ConfigReader() instead
func (b *LiveBouncer) Config(configPath string) error {
	reader, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file '%s': %w", configPath, err)
	}

	return b.ConfigReader(reader)
}

func (b *LiveBouncer) ConfigReader(configReader io.Reader) error {
	content, err := io.ReadAll(configReader)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}
	err = yaml.Unmarshal(content, b)
	if err != nil {
		return fmt.Errorf("unable to unmarshal configuration: %w", err)
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

func (b *LiveBouncer) Init() error {
	var (
		err                error
		apiURL             *url.URL
		client             *http.Client
		caCertPool         *x509.CertPool
		InsecureSkipVerify bool
		ok                 bool
	)
	apiURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return fmt.Errorf("local API Url '%s': %w", b.APIUrl, err)
	}

	if b.CAPath != "" {
		log.Infof("Using CA cert '%s'", b.CAPath)
		caCert, err := ioutil.ReadFile(b.CAPath)
		if err != nil {
			return fmt.Errorf("unable to load CA certificate '%s': %w", b.CAPath, err)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	} else {
		caCertPool = nil
	}

	if b.InsecureSkipVerify == nil {
		InsecureSkipVerify = false
	} else {
		InsecureSkipVerify = *b.InsecureSkipVerify

	}

	if b.APIKey != "" {
		var transport *apiclient.APIKeyTransport
		log.Infof("Using API key auth")
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

		log.Infof("Using cert auth")
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

	return nil
}

func (b *LiveBouncer) Get(value string) (*models.GetDecisionsResponse, error) {
	filter := apiclient.DecisionsListOpts{
		IPEquals: &value,
	}

	decision, resp, err := b.APIClient.Decisions.List(context.Background(), filter)
	if err != nil {
		if resp != nil && resp.Response != nil {
			resp.Response.Body.Close()
		}
		return &models.GetDecisionsResponse{}, err
	}
	if resp != nil && resp.Response != nil {
		resp.Response.Body.Close()
	}

	return decision, nil
}
