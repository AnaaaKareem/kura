# Grafana Alloy Configuration for Kura LMS

This directory configures Grafana Alloy as the unified telemetry collector for Kura LMS.

## What is Grafana Alloy?

Grafana Alloy is Grafana's official, open-source telemetry collector (the modern successor to Promtail and Grafana Agent). It supports OpenTelemetry, Prometheus metrics, and Loki log streams in a single unified process.

## How it Works in Kura

1. **Log Ingestion:** Alloy mounts the shared `nginx_logs` volume read-only at `/var/log/nginx`.
2. **Tagging:** It attaches metadata tags (`service="nginx"`, `env="production"`, `component="reverse-proxy"`) to incoming log entries.
3. **Forwarding:** Streams processed logs over HTTP to `http://loki:3100/loki/api/v1/push`.
4. **Metrics:** Scrapes its own health metrics and Vault over verified HTTPS, then forwards them to Prometheus with the remote-write receiver. Additional service exporters are being added in WP3.

The metrics component syntax follows the [Grafana Alloy v1.21
`prometheus.scrape`](https://grafana.com/docs/alloy/v1.21/reference/components/prometheus/prometheus.scrape/)
and [`prometheus.remote_write`](https://grafana.com/docs/alloy/v1.21/reference/components/prometheus/prometheus.remote_write/)
documentation, checked 6 November 2026 against the pinned Alloy image `v1.21.3`.
