// Copyright 2021 The Sigstore Authors.
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
//

package server

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"sigs.k8s.io/release-utils/version"
)

var (
	metricNewEntries prometheus.Counter
	MetricLatency    *prometheus.HistogramVec
	RequestsCount    *prometheus.CounterVec
)

// InitMetrics will create a single registry to share across the application
func InitMetrics() *prometheus.Registry {
	return sync.OnceValue[*prometheus.Registry](func() *prometheus.Registry {

		reg := prometheus.NewRegistry()
		metricsFactory := promauto.With(reg)
		metricNewEntries = metricsFactory.NewCounter(prometheus.CounterOpts{
			Name: "fulcio_new_certs",
			Help: "The total number of certificates generated",
		})

		MetricLatency = metricsFactory.NewHistogramVec(prometheus.HistogramOpts{
			Name: "fulcio_api_latency",
			Help: "API Latency on calls",
		}, []string{"code", "method"})

		RequestsCount = metricsFactory.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Count all HTTP requests",
		}, []string{"code", "method"})

		_ = metricsFactory.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "fulcio",
				Name:      "build_info",
				Help:      "A metric with a constant '1' value labeled by version, revision, branch, and goversion from which fulcio was built.",
				ConstLabels: prometheus.Labels{
					"version":    version.GetVersionInfo().GitVersion,
					"revision":   version.GetVersionInfo().GitCommit,
					"build_date": version.GetVersionInfo().BuildDate,
					"goversion":  version.GetVersionInfo().GoVersion,
				},
			},
			func() float64 { return 1 },
		)
		return reg
	})()
}
