// Package coreclient is heain-job's only connection to heain-core: a
// plain HTTP/mTLS client against heain-core's already-implemented P1-P4
// endpoints. It never imports any heain-core package — the wire
// contract (JSON request/response shapes below) is duplicated here
// deliberately, matching how any external, independently-versioned
// client of a network API is expected to work. This is the same
// client-per-target-identity mTLS pattern heain-core's own
// dispatch.HTTPCandidateCapacityFetcher already uses between its own
// nodes (see heain-core's internal/protocol/dispatch/httpfetcher.go).
package coreclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Client talks to one heain-core node over mTLS.
type Client struct {
	BaseURL    string
	httpClient *http.Client
}

// TLSConfig holds the client certificate/key and CA needed to
// authenticate to a heain-core node, issued by that deployment's own
// PKI. heain-job never has a copy of heain-core's own CA key — only an
// operator-provisioned client cert/key pair and the CA's public
// certificate to verify the server.
type TLSConfig struct {
	ClientCertFile string
	ClientKeyFile  string
	CAFile         string
	ServerName     string // the target node's certificate CN/SAN
}

// New builds a Client authenticated against a single heain-core node.
func New(baseURL string, cfg TLSConfig) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("coreclient: loading client cert: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("coreclient: reading CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("coreclient: no valid CA certs found in %s", cfg.CAFile)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
	}
	return &Client{
		BaseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// --- P1 /ingest ---

type IngestRequest struct {
	Payload        []byte         `json:"payload"`
	Classification map[string]any `json:"classification"`
}

type IngestResponse struct {
	TicketID string `json:"ticket_id"`
}

func (c *Client) Ingest(ctx context.Context, req IngestRequest) (*IngestResponse, error) {
	var resp IngestResponse
	if err := c.postJSON(ctx, "/ingest", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// --- P2 /dispatch ---

type Candidate struct {
	WorkerID string `json:"worker_id"`
	Addr     string `json:"addr"`
}

type DispatchRequest struct {
	JobID        string      `json:"job_id"`
	Candidates   []Candidate `json:"candidates,omitempty"`
	Requirements any         `json:"requirements,omitempty"`
}

type DispatchResponse struct {
	WorkerID  string    `json:"worker_id"`
	LeaseID   string    `json:"lease_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Client) Dispatch(ctx context.Context, req DispatchRequest) (*DispatchResponse, error) {
	var resp DispatchResponse
	if err := c.postJSON(ctx, "/dispatch", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// --- P3 /execute ---

type ExecuteRequest struct {
	TicketID string `json:"ticket_id"`
}

type ExecuteResponse struct {
	Staged       bool   `json:"staged"`
	OutputBase64 string `json:"output_base64,omitempty"`
}

func (c *Client) Execute(ctx context.Context, req ExecuteRequest) (*ExecuteResponse, error) {
	var resp ExecuteResponse
	if err := c.postJSON(ctx, "/execute", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// --- P4 /staging/confirm-retrieval, /staging/request-erasure ---

type StagingTicketRequest struct {
	TicketID string `json:"ticket_id"`
}

func (c *Client) ConfirmRetrieval(ctx context.Context, ticketID string) error {
	return c.postJSON(ctx, "/staging/confirm-retrieval", StagingTicketRequest{TicketID: ticketID}, nil)
}

func (c *Client) RequestErasure(ctx context.Context, ticketID string) error {
	return c.postJSON(ctx, "/staging/request-erasure", StagingTicketRequest{TicketID: ticketID}, nil)
}

// postJSON POSTs a JSON body and decodes a JSON response, if out != nil.
func (c *Client) postJSON(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("coreclient: encoding request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("coreclient: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("coreclient: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("coreclient: %s returned HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("coreclient: decoding response from %s: %w", path, err)
	}
	return nil
}
