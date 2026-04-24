package prometheus_exporter

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kalgurn/github-rate-limits-prometheus-exporter/internal/github_client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	githubAccount = os.Getenv("GITHUB_ACCOUNT_NAME")
)

func newLimitsCollector(ghClient github_client.GithubClient) *LimitsCollector {
	return &LimitsCollector{
		LimitTotal: prometheus.NewDesc(prometheus.BuildFQName("github", "limit", "total"),
			"Total limit of requests for the installation",
			nil, prometheus.Labels{
				"account": githubAccount,
			}),
		LimitRemaining: prometheus.NewDesc(prometheus.BuildFQName("github", "limit", "remaining"),
			"Amount of remaining requests for the installation",
			nil, prometheus.Labels{
				"account": githubAccount,
			}),
		LimitUsed: prometheus.NewDesc(prometheus.BuildFQName("github", "limit", "used"),
			"Amount of used requests for the installation",
			nil, prometheus.Labels{
				"account": githubAccount,
			}),
		SecondsLeft: prometheus.NewDesc(prometheus.BuildFQName("github", "limit", "time_left_seconds"),
			"Time left in seconds until rate limit gets reset for the installation",
			nil, prometheus.Labels{
				"account": githubAccount,
			}),

		ghClient: ghClient,
	}
}

func (collector *LimitsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.LimitTotal
	ch <- collector.LimitRemaining
	ch <- collector.LimitUsed
	ch <- collector.SecondsLeft
}

func (collector *LimitsCollector) Collect(ch chan<- prometheus.Metric) {
	ghc, err := collector.ghClient.InitClient()
	if err != nil {
		log.Printf("failed to initialize GitHub client: %s", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	limits, err := github_client.GetRemainingLimits(ghc, ctx)
	if err != nil {
		log.Printf("failed to retrieve remaining limits: %s", err.Error())
		return
	}
	log.Printf("Collected metrics for %s", githubAccount)
	log.Printf("Limit: %d | Used: %d | Remaining: %d", limits.Limit, limits.Used, limits.Remaining)
	//Write latest value for each metric in the prometheus metric channel.
	//Note that you can pass CounterValue, GaugeValue, or UntypedValue types here.
	m1 := prometheus.MustNewConstMetric(collector.LimitTotal, prometheus.GaugeValue, float64(limits.Limit))
	m2 := prometheus.MustNewConstMetric(collector.LimitRemaining, prometheus.GaugeValue, float64(limits.Remaining))
	m3 := prometheus.MustNewConstMetric(collector.LimitUsed, prometheus.GaugeValue, float64(limits.Used))
	m4 := prometheus.MustNewConstMetric(collector.SecondsLeft, prometheus.GaugeValue, limits.SecondsLeft)
	m1 = prometheus.NewMetricWithTimestamp(time.Now(), m1)
	m2 = prometheus.NewMetricWithTimestamp(time.Now(), m2)
	m3 = prometheus.NewMetricWithTimestamp(time.Now(), m3)
	m4 = prometheus.NewMetricWithTimestamp(time.Now(), m4)
	ch <- m1
	ch <- m2
	ch <- m3
	ch <- m4
}

func Run() {
	auth, err := github_client.InitConfig()
	if err != nil {
		log.Fatalf("failed to initialize GitHub client config: %s", err.Error())
	}
	limit := newLimitsCollector(auth)
	prometheus.NewRegistry()
	prometheus.MustRegister(limit)

	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(":2112", nil); err != nil {
		log.Fatalf("HTTP listener failed: %s", err.Error())
	}
}
