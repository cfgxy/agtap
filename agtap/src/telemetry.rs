use std::time::{Duration, SystemTime};

use opentelemetry::metrics::{Histogram, MeterProvider as _};
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer, TracerProvider as _};
use opentelemetry::{Context, KeyValue, StringValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{
    Aggregation, Instrument, PeriodicReader, SdkMeterProvider, Stream,
};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram as PromHistogram;
use prometheus_client::registry::Registry;

use crate::output::{AgentEvent, CallKind};

const DURATION_BUCKETS: &[f64] = &[
    0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 180.0, 300.0,
];
const TOKEN_BUCKETS: &[f64] = &[
    10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0, 200000.0, 500000.0,
];
const TTFT_BUCKETS: &[f64] = &[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
const BYTES_BUCKETS: &[f64] = &[
    256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0,
];

pub struct TelemetryHandle {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    duration_histogram: Histogram<f64>,
    token_histogram: Histogram<f64>,
    ttft_histogram: Histogram<f64>,
    request_bytes_histogram: Histogram<f64>,
    response_bytes_histogram: Histogram<f64>,
}

pub struct TelemetryConfig {
    pub endpoint: String,
    pub boot_time_ns: u64,
}

pub fn init(config: TelemetryConfig) -> anyhow::Result<TelemetryHandle> {
    let base = config.endpoint.trim_end_matches('/');

    let resource = Resource::builder()
        .with_service_name("agtap")
        .with_attribute(KeyValue::new("agtap.version", env!("CARGO_PKG_VERSION")))
        .build();

    // Trace exporter + provider
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/traces"))
        .build()?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter)
        .build();

    // Metric exporter + provider
    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/metrics"))
        .build()?;

    let metric_reader = PeriodicReader::builder(metric_exporter)
        .with_interval(Duration::from_secs(10))
        .build();

    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(metric_reader)
        .with_view(|inst: &Instrument| {
            if inst.name == "gen_ai.client.operation.duration" {
                Some(
                    Stream::new().aggregation(Aggregation::ExplicitBucketHistogram {
                        boundaries: DURATION_BUCKETS.to_vec(),
                        record_min_max: true,
                    }),
                )
            } else {
                None
            }
        })
        .with_view(|inst: &Instrument| {
            if inst.name == "gen_ai.client.token.usage" {
                Some(
                    Stream::new().aggregation(Aggregation::ExplicitBucketHistogram {
                        boundaries: TOKEN_BUCKETS.to_vec(),
                        record_min_max: true,
                    }),
                )
            } else {
                None
            }
        })
        .with_view(|inst: &Instrument| {
            if inst.name == "gen_ai.server.time_to_first_token" {
                Some(
                    Stream::new().aggregation(Aggregation::ExplicitBucketHistogram {
                        boundaries: TTFT_BUCKETS.to_vec(),
                        record_min_max: true,
                    }),
                )
            } else {
                None
            }
        })
        .with_view(|inst: &Instrument| {
            if inst.name == "gen_ai.client.request.size"
                || inst.name == "gen_ai.client.response.size"
            {
                Some(
                    Stream::new().aggregation(Aggregation::ExplicitBucketHistogram {
                        boundaries: BYTES_BUCKETS.to_vec(),
                        record_min_max: true,
                    }),
                )
            } else {
                None
            }
        })
        .build();

    let meter = meter_provider.meter("agtap");

    let duration_histogram = meter
        .f64_histogram("gen_ai.client.operation.duration")
        .with_unit("s")
        .build();

    let token_histogram = meter
        .f64_histogram("gen_ai.client.token.usage")
        .with_unit("{token}")
        .build();

    let ttft_histogram = meter
        .f64_histogram("gen_ai.server.time_to_first_token")
        .with_unit("s")
        .build();

    let request_bytes_histogram = meter
        .f64_histogram("gen_ai.client.request.size")
        .with_unit("By")
        .build();

    let response_bytes_histogram = meter
        .f64_histogram("gen_ai.client.response.size")
        .with_unit("By")
        .build();

    Ok(TelemetryHandle {
        tracer_provider,
        meter_provider,
        duration_histogram,
        token_histogram,
        ttft_histogram,
        request_bytes_histogram,
        response_bytes_histogram,
    })
}

pub fn record_event(handle: &TelemetryHandle, event: &AgentEvent) {
    // Exhaustive destructuring to catch field additions at compile time
    let AgentEvent {
        ts: _,
        wall_ns,
        ref id,
        pid,
        ref process,
        ref provider,
        ref server_address,
        kind,
        ref model,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
        latency_ms,
        ref stop_reason,
        ref tools,
        streaming,
        ttft_ms,
        body_path: _,
        request_bytes,
        response_bytes,
    } = *event;

    // Build span attributes
    let operation_name = if kind == CallKind::McpCall {
        "mcp"
    } else {
        "chat"
    };
    let provider_str: String = if kind == CallKind::McpCall {
        "mcp".into()
    } else {
        provider.clone()
    };

    let mut attrs = vec![
        KeyValue::new("gen_ai.operation.name", operation_name),
        KeyValue::new("gen_ai.provider.name", provider_str.clone()),
        KeyValue::new("gen_ai.request.model", model.clone()),
        KeyValue::new("gen_ai.response.id", id.clone()),
        KeyValue::new("gen_ai.response.finish_reasons", stop_reason.clone()),
        KeyValue::new("server.address", server_address.clone()),
        KeyValue::new("agtap.pid", pid as i64),
        KeyValue::new("agtap.process", process.clone()),
        KeyValue::new("agtap.kind", kind.as_str().to_string()),
        KeyValue::new("agtap.streaming", streaming),
    ];

    if let Some(input) = input_tokens {
        attrs.push(KeyValue::new("gen_ai.usage.input_tokens", input as i64));
    }
    if let Some(output) = output_tokens {
        attrs.push(KeyValue::new("gen_ai.usage.output_tokens", output as i64));
    }

    if let Some(cc) = cache_creation_input_tokens {
        attrs.push(KeyValue::new(
            "gen_ai.usage.cache_creation_input_tokens",
            cc as i64,
        ));
    }
    if let Some(cr) = cache_read_input_tokens {
        attrs.push(KeyValue::new(
            "gen_ai.usage.cache_read_input_tokens",
            cr as i64,
        ));
    }

    let tools_values: Vec<StringValue> =
        tools.iter().map(|t| StringValue::from(t.clone())).collect();
    if !tools_values.is_empty() {
        attrs.push(KeyValue::new(
            "agtap.tools",
            opentelemetry::Value::Array(tools_values.into()),
        ));
    }

    if let Some(ttft) = ttft_ms {
        attrs.push(KeyValue::new("agtap.ttft_ms", ttft as i64));
    }
    if let Some(rb) = request_bytes {
        attrs.push(KeyValue::new("agtap.request_bytes", rb as i64));
    }
    if let Some(rb) = response_bytes {
        attrs.push(KeyValue::new("agtap.response_bytes", rb as i64));
    }

    // Build span with correct wall-clock timestamps
    let tracer = handle.tracer_provider.tracer("agtap");
    let span_name = format!("{} {}", operation_name, model);
    let duration = Duration::from_millis(latency_ms);

    let start_time = SystemTime::UNIX_EPOCH + Duration::from_nanos(wall_ns);

    let end_time = start_time + duration;

    let span = tracer
        .span_builder(span_name)
        .with_kind(SpanKind::Client)
        .with_start_time(start_time)
        .with_end_time(end_time)
        .with_attributes(attrs)
        .start(&tracer);

    // End the span immediately (timestamps already set)
    let cx = Context::current_with_span(span);
    cx.span().end();

    // Record metrics
    let metric_attrs = vec![
        KeyValue::new("gen_ai.request.model", model.clone()),
        KeyValue::new("gen_ai.provider.name", provider_str),
    ];

    handle
        .duration_histogram
        .record(latency_ms as f64 / 1000.0, &metric_attrs);

    if let Some(input) = input_tokens {
        handle.token_histogram.record(
            input as f64,
            &[
                KeyValue::new("gen_ai.request.model", model.clone()),
                KeyValue::new("gen_ai.token.type", "input"),
            ],
        );
    }
    if let Some(output) = output_tokens {
        handle.token_histogram.record(
            output as f64,
            &[
                KeyValue::new("gen_ai.request.model", model.clone()),
                KeyValue::new("gen_ai.token.type", "output"),
            ],
        );
    }
    if let Some(cc) = cache_creation_input_tokens {
        handle.token_histogram.record(
            cc as f64,
            &[
                KeyValue::new("gen_ai.request.model", model.clone()),
                KeyValue::new("gen_ai.token.type", "cache_creation_input"),
            ],
        );
    }
    if let Some(cr) = cache_read_input_tokens {
        handle.token_histogram.record(
            cr as f64,
            &[
                KeyValue::new("gen_ai.request.model", model.clone()),
                KeyValue::new("gen_ai.token.type", "cache_read_input"),
            ],
        );
    }

    if let Some(ttft) = ttft_ms {
        handle
            .ttft_histogram
            .record(ttft as f64 / 1000.0, &metric_attrs);
    }

    if let Some(rb) = request_bytes {
        handle
            .request_bytes_histogram
            .record(rb as f64, &metric_attrs);
    }
    if let Some(rb) = response_bytes {
        handle
            .response_bytes_histogram
            .record(rb as f64, &metric_attrs);
    }
}

pub fn shutdown(handle: TelemetryHandle) {
    if let Err(e) = handle.tracer_provider.shutdown() {
        eprintln!("agtap: OTel tracer shutdown error: {}", e);
    }
    if let Err(e) = handle.meter_provider.shutdown() {
        eprintln!("agtap: OTel meter shutdown error: {}", e);
    }
}

// ── Prometheus scrape endpoint ─────────────────────────────────────────

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct MetricLabels {
    model: String,
    provider: String,
    process: String,
    kind: String,
    streaming: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TokenLabels {
    model: String,
    provider: String,
    process: String,
    kind: String,
    streaming: String,
    token_type: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct CounterLabels {
    provider: String,
    process: String,
    kind: String,
    streaming: String,
    status: String,
}

pub struct PrometheusMetrics {
    registry: Registry,
    duration: Family<MetricLabels, PromHistogram>,
    tokens: Family<TokenLabels, PromHistogram>,
    ttft: Family<MetricLabels, PromHistogram>,
    requests: Family<CounterLabels, Counter>,
    request_bytes: Family<MetricLabels, PromHistogram>,
    response_bytes: Family<MetricLabels, PromHistogram>,
}

pub fn init_prometheus() -> PrometheusMetrics {
    let mut registry = Registry::default();

    let duration = Family::<MetricLabels, PromHistogram>::new_with_constructor(|| {
        PromHistogram::new(DURATION_BUCKETS.iter().copied())
    });
    registry.register(
        "agtap_request_duration_seconds",
        "LLM/MCP call latency",
        duration.clone(),
    );

    let tokens = Family::<TokenLabels, PromHistogram>::new_with_constructor(|| {
        PromHistogram::new(TOKEN_BUCKETS.iter().copied())
    });
    registry.register(
        "agtap_token_count",
        "Input/output token count",
        tokens.clone(),
    );

    let ttft = Family::<MetricLabels, PromHistogram>::new_with_constructor(|| {
        PromHistogram::new(TTFT_BUCKETS.iter().copied())
    });
    registry.register(
        "agtap_time_to_first_token_seconds",
        "Time to first token",
        ttft.clone(),
    );

    let requests = Family::<CounterLabels, Counter>::default();
    registry.register("agtap_requests", "Total LLM/MCP requests", requests.clone());

    let request_bytes = Family::<MetricLabels, PromHistogram>::new_with_constructor(|| {
        PromHistogram::new(BYTES_BUCKETS.iter().copied())
    });
    registry.register(
        "agtap_request_bytes",
        "Request body size in bytes",
        request_bytes.clone(),
    );

    let response_bytes = Family::<MetricLabels, PromHistogram>::new_with_constructor(|| {
        PromHistogram::new(BYTES_BUCKETS.iter().copied())
    });
    registry.register(
        "agtap_response_bytes",
        "Response body size in bytes",
        response_bytes.clone(),
    );

    PrometheusMetrics {
        registry,
        duration,
        tokens,
        ttft,
        requests,
        request_bytes,
        response_bytes,
    }
}

pub fn record_prometheus(prom: &PrometheusMetrics, event: &AgentEvent) {
    let provider = if event.kind == CallKind::McpCall {
        "mcp"
    } else {
        &event.provider
    };

    let model = &event.model;
    let provider_owned = provider.to_string();
    let process = event.process.clone();
    let kind_str = event.kind.as_str().to_string();
    let streaming_str = event.streaming.to_string();

    let labels = MetricLabels {
        model: model.clone(),
        provider: provider_owned.clone(),
        process: process.clone(),
        kind: kind_str.clone(),
        streaming: streaming_str.clone(),
    };

    prom.duration
        .get_or_create(&labels)
        .observe(event.latency_ms as f64 / 1000.0);

    let observe_tokens = |token_type: &str, count: f64| {
        prom.tokens
            .get_or_create(&TokenLabels {
                model: model.clone(),
                provider: provider_owned.clone(),
                process: process.clone(),
                kind: kind_str.clone(),
                streaming: streaming_str.clone(),
                token_type: token_type.to_string(),
            })
            .observe(count);
    };

    if let Some(input) = event.input_tokens {
        observe_tokens("input", input as f64);
    }
    if let Some(output) = event.output_tokens {
        observe_tokens("output", output as f64);
    }
    if let Some(cc) = event.cache_creation_input_tokens {
        observe_tokens("cache_creation_input", cc as f64);
    }
    if let Some(cr) = event.cache_read_input_tokens {
        observe_tokens("cache_read_input", cr as f64);
    }

    if let Some(ttft) = event.ttft_ms {
        prom.ttft
            .get_or_create(&labels)
            .observe(ttft as f64 / 1000.0);
    }

    let status = if event.stop_reason.starts_with("error:") {
        "error"
    } else {
        "ok"
    };
    prom.requests
        .get_or_create(&CounterLabels {
            provider: provider_owned,
            process,
            kind: kind_str,
            streaming: streaming_str,
            status: status.to_string(),
        })
        .inc();

    if let Some(rb) = event.request_bytes {
        prom.request_bytes.get_or_create(&labels).observe(rb as f64);
    }

    if let Some(rb) = event.response_bytes {
        prom.response_bytes
            .get_or_create(&labels)
            .observe(rb as f64);
    }
}

pub fn encode_prometheus(prom: &PrometheusMetrics) -> String {
    let mut buf = String::new();
    prometheus_client::encoding::text::encode(&mut buf, &prom.registry).unwrap();
    buf
}

pub async fn serve_prometheus(
    listener: tokio::net::TcpListener,
    metrics: std::sync::Arc<PrometheusMetrics>,
) {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::{body::Incoming, Method, Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let metrics = metrics.clone();
                async move {
                    if req.method() == Method::GET && req.uri().path() == "/metrics" {
                        let body = encode_prometheus(&metrics);
                        Response::builder()
                            .header(
                                "content-type",
                                "application/openmetrics-text; version=1.0.0; charset=utf-8",
                            )
                            .body(Full::new(Bytes::from(body)))
                    } else {
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::new()))
                    }
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::AgentEvent;

    #[test]
    fn test_init_registers_all_metrics() {
        let prom = init_prometheus();
        let output = encode_prometheus(&prom);
        for name in [
            "agtap_request_duration_seconds",
            "agtap_token_count",
            "agtap_time_to_first_token_seconds",
            "agtap_requests",
            "agtap_request_bytes",
            "agtap_response_bytes",
        ] {
            assert!(
                output.contains(&format!("# TYPE {name}")),
                "missing TYPE for {name}"
            );
        }
        assert!(output.ends_with("# EOF\n"), "output must end with # EOF");
    }

    #[test]
    fn test_record_basic_event() {
        let prom = init_prometheus();
        let event = AgentEvent::test_default();
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            output.contains("agtap_request_duration_seconds_bucket"),
            "missing duration bucket"
        );
        assert!(
            output.contains("agtap_token_count_bucket"),
            "missing token bucket"
        );
        assert!(
            output.contains("agtap_time_to_first_token_seconds_bucket"),
            "missing ttft bucket"
        );
        assert!(
            output.contains("agtap_requests_total"),
            "missing requests counter"
        );
    }

    #[test]
    fn test_record_cache_tokens() {
        let prom = init_prometheus();
        let mut event = AgentEvent::test_default();
        event.cache_creation_input_tokens = Some(500);
        event.cache_read_input_tokens = Some(300);
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            output.contains("token_type=\"cache_creation_input\""),
            "missing cache_creation_input token_type"
        );
        assert!(
            output.contains("token_type=\"cache_read_input\""),
            "missing cache_read_input token_type"
        );
    }

    #[test]
    fn test_record_no_ttft_when_none() {
        let prom = init_prometheus();
        let mut event = AgentEvent::test_default();
        event.ttft_ms = None;
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        // TTFT type line should exist but no observations (sum=0, count=0)
        assert!(output.contains("# TYPE agtap_time_to_first_token_seconds"));
        assert!(
            !output.contains("agtap_time_to_first_token_seconds_bucket{"),
            "ttft should have no observations when ttft_ms is None"
        );
    }

    #[test]
    fn test_mcp_call_provider_label() {
        let prom = init_prometheus();
        let mut event = AgentEvent::test_default();
        event.kind = CallKind::McpCall;
        event.provider = "some_server".into();
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            output.contains("provider=\"mcp\""),
            "MCP events should have provider=mcp"
        );
        assert!(
            output.contains("kind=\"mcp_call\""),
            "MCP events should have kind=mcp_call"
        );
    }

    #[test]
    fn test_error_status_label() {
        let prom = init_prometheus();
        let mut event = AgentEvent::test_default();
        event.stop_reason = "error:rate_limit_error".into();
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            output.contains("status=\"error\""),
            "error: stop_reason should produce status=error"
        );
    }

    #[test]
    fn test_mcp_no_token_observations() {
        let prom = init_prometheus();
        let mut event = AgentEvent::test_default();
        event.kind = CallKind::McpCall;
        event.provider = "some_server".into();
        event.input_tokens = None;
        event.output_tokens = None;
        event.cache_creation_input_tokens = None;
        event.cache_read_input_tokens = None;
        event.ttft_ms = None;
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            !output.contains("agtap_token_count_bucket"),
            "MCP event with no tokens should not produce token observations"
        );
        assert!(
            output.contains("provider=\"mcp\""),
            "MCP event should have provider=mcp on duration histogram"
        );
    }

    #[test]
    fn test_none_tokens_skipped() {
        let prom = init_prometheus();
        let mut event = AgentEvent::test_default();
        event.input_tokens = None;
        event.output_tokens = None;
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            !output.contains("token_type=\"input\""),
            "None input_tokens should not produce token observations"
        );
        assert!(
            !output.contains("token_type=\"output\""),
            "None output_tokens should not produce token observations"
        );
    }

    #[test]
    fn test_bytes_histograms() {
        let prom = init_prometheus();
        let event = AgentEvent::test_default();
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            output.contains("agtap_request_bytes_bucket"),
            "missing request_bytes bucket"
        );
        assert!(
            output.contains("agtap_response_bytes_bucket"),
            "missing response_bytes bucket"
        );
    }

    #[test]
    fn test_process_label() {
        let prom = init_prometheus();
        let mut event = AgentEvent::test_default();
        event.process = "claude-code".into();
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            output.contains("process=\"claude-code\""),
            "process label should appear in metrics output"
        );
    }

    #[test]
    fn test_kind_label_on_histograms() {
        let prom = init_prometheus();
        let event = AgentEvent::test_default();
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            output.contains("kind=\"llm_call\""),
            "kind label should appear on duration histogram"
        );
    }

    #[test]
    fn test_streaming_label_on_histograms() {
        let prom = init_prometheus();
        let mut event = AgentEvent::test_default();
        event.streaming = true;
        record_prometheus(&prom, &event);
        let output = encode_prometheus(&prom);

        assert!(
            output.contains("streaming=\"true\""),
            "streaming label should appear on histograms"
        );
    }
}
