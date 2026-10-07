package heain

// For a gateway app (core Step 4.6a): the routes core exposes, and an mTLS
// client to the app instance that serves one.

import (
	"context"
	"net/http"
)

// GatewayRoute is one exposure (core gateway.exposures) as core reports it.
type GatewayRoute struct {
	App        string            `json:"app"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Roles      []string          `json:"roles,omitempty"`
	Auth       string            `json:"auth"` // user | anonymous
	RatePerMin int               `json:"rate_per_min,omitempty"`
	Comment    string            `json:"comment,omitempty"`
	Capability string            `json:"capability,omitempty"`
	Formal     *bool             `json:"formal,omitempty"`
	Lane       string            `json:"lane,omitempty"`
	Status     string            `json:"status"` // ok | not_public | no_instance
	Instances  []GatewayInstance `json:"instances"`
}

// GatewayInstance is a live instance that serves a route.
type GatewayInstance struct {
	InstanceID   string `json:"instance_id"`
	AppVersion   string `json:"app_version"`
	EndpointBase string `json:"endpoint_base"`
}

// GatewayRoutes asks core for the exposed routes (only an app listed in
// core's gateway.apps may).
func (a *App) GatewayRoutes(ctx context.Context) ([]GatewayRoute, uint64, error) {
	var out struct {
		ConfigVersion uint64         `json:"config_version"`
		Routes        []GatewayRoute `json:"routes"`
	}
	if _, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/gateway/routes", nil, nil, &out); err != nil {
		return nil, 0, err
	}
	return out.Routes, out.ConfigVersion, nil
}

// AppClient is an mTLS client that talks only to the app instance
// <appID>.<instanceID> (its certificate is checked to be that instance's).
func (a *App) AppClient(appID, instanceID string) (*http.Client, error) {
	return a.appClient(appID + "." + instanceID)
}
