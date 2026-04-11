package cli

import (
	"net/http"

	"connectrpc.com/connect"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
)

type Clients struct {
	Sid      vinberov1connect.SidFunctionServiceClient
	Hv4      vinberov1connect.Headendv4ServiceClient
	Hv6      vinberov1connect.Headendv6ServiceClient
	Hl2      vinberov1connect.HeadendL2ServiceClient
	Peer     vinberov1connect.BdPeerServiceClient
	Resource vinberov1connect.NetworkResourceServiceClient
	Fdb      vinberov1connect.FdbServiceClient
	Stats    vinberov1connect.StatsServiceClient
}

func NewClients(serverURL string) *Clients {
	httpClient := http.DefaultClient
	opts := []connect.ClientOption{}

	return &Clients{
		Sid:      vinberov1connect.NewSidFunctionServiceClient(httpClient, serverURL, opts...),
		Hv4:      vinberov1connect.NewHeadendv4ServiceClient(httpClient, serverURL, opts...),
		Hv6:      vinberov1connect.NewHeadendv6ServiceClient(httpClient, serverURL, opts...),
		Hl2:      vinberov1connect.NewHeadendL2ServiceClient(httpClient, serverURL, opts...),
		Peer:     vinberov1connect.NewBdPeerServiceClient(httpClient, serverURL, opts...),
		Resource: vinberov1connect.NewNetworkResourceServiceClient(httpClient, serverURL, opts...),
		Fdb:      vinberov1connect.NewFdbServiceClient(httpClient, serverURL, opts...),
		Stats:    vinberov1connect.NewStatsServiceClient(httpClient, serverURL, opts...),
	}
}
