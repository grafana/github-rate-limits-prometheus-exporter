package prometheus_exporter

import (
	"github.com/grafana/github-rate-limits-prometheus-exporter/internal/github_client"
	"github.com/prometheus/client_golang/prometheus"
)

type LimitsCollector struct {
	LimitTotal     *prometheus.Desc
	LimitRemaining *prometheus.Desc
	LimitUsed      *prometheus.Desc
	SecondsLeft    *prometheus.Desc
	BuildInfo      *prometheus.Desc

	ghClient github_client.GithubClient
}
