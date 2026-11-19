package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	xmaps "github.com/certimate-go/certimate/pkg/utils/maps"

	"github.com/certimate-go/certimate/pkg/plugin"
	"github.com/go-acme/lego/v5/challenge/dns01"

	"github.com/certimate-go/certimate/pkg/core"
	chlgimpl "github.com/certimate-go/plugin-provider-yandexcloud-dns-acmedns01challenger/internal/yandexcloud"
)

type accessConfig struct {
	FolderId          string `json:"folderId"`
	ServiceAccountKey string `json:"serviceAccountKey"`
}

type server struct {
	mu         sync.Mutex
	challenger core.ACMEChallenger
}

type dnsSettings struct {
	Nameservers        []string `json:"nameservers"`
	DisableFollowCNAME bool     `json:"disableFollowCNAME"`
	TTL                int      `json:"ttl"`
}

func (*server) RuntimeConfig(context.Context) (json.RawMessage, error) {
	timeout, interval := chlgimpl.PropagationTiming()
	return json.Marshal(map[string]int64{
		"propagation_timeout_seconds":          int64(max(timeout, 0) / time.Second),
		"propagation_polling_interval_seconds": int64(max(interval, 0) / time.Second),
	})
}

func (s *server) Process(ctx context.Context, req *plugin.Request, _ *slog.Logger) (*plugin.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.challenger == nil {
		var settings dnsSettings
		if err := json.Unmarshal([]byte(req.ExtendedConfigJSON), &settings); err != nil {
			return nil, fmt.Errorf("invalid DNS challenge configuration: %w", err)
		}
		if err := os.Setenv("LEGO_DISABLE_CNAME_SUPPORT", strconv.FormatBool(settings.DisableFollowCNAME)); err != nil {
			return nil, err
		}
		dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{RecursiveNameservers: settings.Nameservers}))
		challenger, err := newChallenger(req, settings)
		if err != nil {
			return nil, err
		}
		s.challenger = challenger
	}

	if err := s.challenger.Present(ctx, req.Dns.Domain, req.Dns.Token, req.Dns.KeyAuth); err != nil {
		return nil, err
	}
	return &plugin.Result{Dns: &plugin.DnsResult{}}, nil
}

func (s *server) PostProcess(ctx context.Context, req *plugin.Request, _ *slog.Logger) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.challenger == nil {
		return nil
	}
	return s.challenger.CleanUp(ctx, req.Dns.Domain, req.Dns.Token, req.Dns.KeyAuth)
}

func newChallenger(req *plugin.Request, settings dnsSettings) (core.ACMEChallenger, error) {
	var access map[string]any
	if err := json.Unmarshal([]byte(req.AccessConfigJSON), &access); err != nil {
		return nil, fmt.Errorf("invalid DNS access configuration: %w", err)
	}
	var credentials accessConfig
	if err := xmaps.Populate(access, &credentials); err != nil {
		return nil, fmt.Errorf("failed to populate provider access config: %w", err)
	}

	provider, err := chlgimpl.NewChallenger(&chlgimpl.ChallengerConfig{
		FolderId:          credentials.FolderId,
		ServiceAccountKey: credentials.ServiceAccountKey,

		DnsTTL: settings.TTL,
	})
	return provider, err
}
