# Prometheus Monitoring & Alerting Configuration for Kura LMS

This directory configures the Prometheus time-series monitoring engine.

## Configured Files

- `prometheus.yml`: Scrapes metrics from internal services (Alloy, Alertmanager, Prometheus itself) every 15 seconds.
- `alerts.yml`: Defines evaluation rules for infrastructure downtime and telemetry latency. When a rule condition triggers, Prometheus forwards the alert to Alertmanager.

## Network Security

Prometheus runs entirely on the private `observability` network without public ports exposed. Queries are made internally by Grafana via `http://prometheus:9090`.

