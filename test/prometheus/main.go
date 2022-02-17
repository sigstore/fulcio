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

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

const (
	latencyMetric = "fulcio_api_latency"
	certMetric    = "fulcio_new_certs"
)

func parseMF(url string) (map[string]*dto.MetricFamily, error) {
	resp, err := http.Get(url) // nolint
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parser expfmt.TextParser
	return parser.TextToMetricFamilies(resp.Body)
}

func main() {
	f := flag.String("url", "http://fulcio-server.fulcio-system.svc:2112/metrics", "set url to fetch metrics from")
	flag.Parse()

	mf, err := parseMF(*f)
	if err != nil {
		log.Fatalf("Failed to fetch/parse metrics: %v", err)
	}

	// Just grab the api_latency metric, make sure it's a histogram
	// and just make sure there is at least one 200, and no errors there.
	latency, ok := mf[latencyMetric]
	if !ok || latency == nil {
		log.Fatal("Did not get fulcio_api_latency metric")
	}
	if err := checkLatency(latency); err != nil {
		log.Fatalf("fulcio_api_latency metric failed: %s", err)
	}

	// Then make sure the cert counter went up.
	certCount, ok := mf[certMetric]
	if !ok || certCount == nil {
		log.Fatal("Did not get fulcio_new_certs metric")
	}
	if err := checkCertCount(certCount); err != nil {
		log.Fatalf("fulcio_new_certs metric failed: %s", err)
	}
}

// Make sure latency is a Histogram, and it has a POST with a 201.
func checkLatency(latency *dto.MetricFamily) error {
	if *latency.Type != *dto.MetricType_HISTOGRAM.Enum() {
		return fmt.Errorf("Wrong type, wanted %+v, got: %+v", dto.MetricType_HISTOGRAM.Enum(), latency.Type)
	}
	if len(latency.Metric) != 1 {
		return fmt.Errorf("Got multiple entries, or none for metric, wanted one, got: %+v", latency.Metric)
	}
	// Make sure there's a 'post' and it's a 201.
	var code string
	var method string
	for _, value := range latency.Metric[0].Label {
		if *value.Name == "code" {
			code = *value.Value
		}
		if *value.Name == "method" {
			method = *value.Value
		}
	}
	if code != "201" {
		return fmt.Errorf("unexpected code, wanted 201, got %s", code)
	}
	if method != "post" {
		return fmt.Errorf("unexpected method, wanted post, got %s", method)
	}

	if *latency.Metric[0].Histogram.SampleCount != 1 {
		return fmt.Errorf("Unexpected samplecount, wanted 1, got %d", *latency.Metric[0].Histogram.SampleCount)
	}
	return nil
}

func checkCertCount(certCount *dto.MetricFamily) error {
	if *certCount.Type != *dto.MetricType_COUNTER.Enum() {
		return fmt.Errorf("Wrong type, wanted %+v, got: %+v", dto.MetricType_COUNTER.Enum(), certCount.Type)
	}
	if len(certCount.Metric) != 1 {
		return fmt.Errorf("Got multiple entries, or none for metric, wanted one, got: %+v", certCount.Metric)
	}
	if *certCount.Metric[0].Counter.Value < 1 {
		return fmt.Errorf("Got incorrect cert count, wanted one, got: %f", *certCount.Metric[0].Counter.Value)
	}
	return nil
}
