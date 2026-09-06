/**
 * OpenTelemetry bootstrap — UAM backend → Grafana Cloud (LGTM)
 *
 * Reads the Grafana Cloud OTLP env config (kept in gitignored `.env`):
 *   OTEL_EXPORTER_OTLP_ENDPOINT  https://otlp-gateway-...grafana.net/otlp
 *   OTEL_EXPORTER_OTLP_HEADERS   Authorization=Basic%20<base64>[,K=V...]
 *   OTEL_SERVICE_NAME            (default: uam-backend)
 *
 * Signal endpoints are derived by the OTLP exporters:
 *   {endpoint}/v1/traces  → Tempo
 *   {endpoint}/v1/metrics → Mimir
 *   {endpoint}/v1/logs    → Loki
 *
 * If `OTEL_EXPORTER_OTLP_ENDPOINT` is not set, telemetry is a no-op and the
 * app runs exactly as before (no exporters, no instrumentation).
 *
 * IMPORTANT: import this module BEFORE express/http so the auto-instrumentation
 * can patch those modules (index.ts imports it first).
 */
import {
    diag,
    DiagConsoleLogger,
    DiagLogLevel,
    metrics,
    type Counter,
    type Gauge,
    type Histogram,
    type Meter,
} from '@opentelemetry/api';
import { logs, type Logger } from '@opentelemetry/api-logs';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { BatchLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_NAMESPACE } from '@opentelemetry/semantic-conventions';

let enabled = false;
let sdk: NodeSDK | null = null;
let otelLogger: Logger | null = null;
let meter: Meter | null = null;

// ── Redis circuit-breaker metrics instruments ────────────────────────────────
let redisRequests: Counter | null = null;
let redisSuccess: Counter | null = null;
let redisErrors: Counter | null = null;
let redisTimeouts: Counter | null = null;
let redisCircuitOpen: Counter | null = null;
let redisCircuitHalfOpen: Counter | null = null;
let redisCircuitRejected: Counter | null = null;
let redisCircuitState: Gauge | null = null;
let redisInflight: Gauge | null = null;
let redisLatencyP50: Gauge | null = null;
let redisLatencyP95: Gauge | null = null;
let redisLatencyP99: Gauge | null = null;
let redisErrorRate: Gauge | null = null;
let httpRequests: Counter | null = null;
let httpDuration: Histogram | null = null;

const lastCounterValues = new Map<Counter, number>();

export function isTelemetryEnabled(): boolean {
    return enabled;
}

/** Initialize OTel SDK + instrumentations. Safe to call once; no-op if disabled. */
export function initTelemetry(): boolean {
    const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    if (!endpoint || enabled) {
        return enabled;
    }

    diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.INFO);

    const serviceName = process.env.OTEL_SERVICE_NAME || 'uam-backend';

    sdk = new NodeSDK({
        resource: resourceFromAttributes({
            [SEMRESATTRS_SERVICE_NAME]: serviceName,
            [SEMRESATTRS_SERVICE_NAMESPACE]: 'nginx-rust-api-gateway',
        }),
        traceExporter: new OTLPTraceExporter(),
        metricReaders: [
            new PeriodicExportingMetricReader({
                exporter: new OTLPMetricExporter(),
                exportIntervalMillis: 15_000,
            }),
        ],
        logRecordProcessors: [
            new BatchLogRecordProcessor({ exporter: new OTLPLogExporter() }),
        ],
        instrumentations: [
            new HttpInstrumentation(),
            new ExpressInstrumentation(),
        ],
    });

    sdk.start();
    otelLogger = logs.getLogger(serviceName);
    meter = metrics.getMeter(serviceName);

    redisRequests = meter.createCounter('uam.redis.requests', {
        description: 'Total Redis operations attempted (breaker-protected)',
    });
    redisSuccess = meter.createCounter('uam.redis.success', {
        description: 'Successful Redis operations',
    });
    redisErrors = meter.createCounter('uam.redis.errors', {
        description: 'Redis operation errors (excludes timeouts)',
    });
    redisTimeouts = meter.createCounter('uam.redis.timeouts', {
        description: 'Redis operation timeouts',
    });
    redisCircuitOpen = meter.createCounter('uam.redis.circuit.open', {
        description: 'Times the Redis circuit transitioned to OPEN',
    });
    redisCircuitHalfOpen = meter.createCounter('uam.redis.circuit.half_open', {
        description: 'Times the Redis circuit transitioned to HALF_OPEN',
    });
    redisCircuitRejected = meter.createCounter('uam.redis.circuit.rejected', {
        description: 'Requests rejected because the circuit was OPEN or the concurrency limit was hit',
    });
    redisCircuitState = meter.createGauge('uam.redis.circuit.state', {
        description: 'Redis circuit state (0=CLOSED,1=OPEN,2=HALF_OPEN)',
    });
    redisInflight = meter.createGauge('uam.redis.inflight', {
        description: 'Current Redis operations in flight',
    });
    redisLatencyP50 = meter.createGauge('uam.redis.latency.p50', {
        description: 'Rolling p50 Redis latency in microseconds',
        unit: 'us',
    });
    redisLatencyP95 = meter.createGauge('uam.redis.latency.p95', {
        description: 'Rolling p95 Redis latency in microseconds',
        unit: 'us',
    });
    redisLatencyP99 = meter.createGauge('uam.redis.latency.p99', {
        description: 'Rolling p99 Redis latency in microseconds',
        unit: 'us',
    });
    redisErrorRate = meter.createGauge('uam.redis.error_rate', {
        description: 'Rolling Redis error rate (0.0-1.0)',
    });
    httpRequests = meter.createCounter('uam.http.requests', {
        description: 'Total HTTP requests handled',
    });
    httpDuration = meter.createHistogram('uam.http.duration', {
        description: 'HTTP request duration in seconds',
        unit: 's',
    });

    enabled = true;
    return true;
}

/** Gracefully flush + shut down exporters (call on SIGTERM/SIGINT). */
export async function shutdownTelemetry(): Promise<void> {
    if (sdk) {
        try {
            await sdk.shutdown();
        } finally {
            sdk = null;
        }
    }
}

/** Emit an OTel log record (also mirrored to console). */
export function otelLog(
    level: 'info' | 'warn' | 'error',
    message: string,
    attrs?: Record<string, string | number | boolean>,
): void {
    const severity: Record<string, number> = { info: 9, warn: 13, error: 17 };
    if (otelLogger) {
        otelLogger.emit({
            severityNumber: severity[level],
            severityText: level.toUpperCase(),
            body: message,
            attributes: attrs,
        });
    }
}

function addCounterDelta(counter: Counter | null, current: number): void {
    if (!counter) return;
    const last = lastCounterValues.get(counter) ?? 0;
    if (current > last) counter.add(current - last);
    lastCounterValues.set(counter, current);
}

/** Copy live circuit-breaker state into OTel metrics (called at prom scrape time). */
export function recordOtelRedisMetrics(snapshot: {
    requestsTotal: number;
    successTotal: number;
    errorsTotal: number;
    timeoutsTotal: number;
    circuitOpenTotal: number;
    circuitHalfOpenTotal: number;
    circuitRejectedTotal: number;
    circuitState: number;
    inflight: number;
    p50Us: number;
    p95Us: number;
    p99Us: number;
    errorRate: number;
}): void {
    if (!enabled) return;
    addCounterDelta(redisRequests, snapshot.requestsTotal);
    addCounterDelta(redisSuccess, snapshot.successTotal);
    addCounterDelta(redisErrors, snapshot.errorsTotal);
    addCounterDelta(redisTimeouts, snapshot.timeoutsTotal);
    addCounterDelta(redisCircuitOpen, snapshot.circuitOpenTotal);
    addCounterDelta(redisCircuitHalfOpen, snapshot.circuitHalfOpenTotal);
    addCounterDelta(redisCircuitRejected, snapshot.circuitRejectedTotal);
    redisCircuitState?.record(snapshot.circuitState);
    redisInflight?.record(snapshot.inflight);
    redisLatencyP50?.record(snapshot.p50Us);
    redisLatencyP95?.record(snapshot.p95Us);
    redisLatencyP99?.record(snapshot.p99Us);
    redisErrorRate?.record(snapshot.errorRate);
}

/** Record an HTTP request into OTel metrics (called from the prom middleware). */
export function recordOtelHttpRequest(
    method: string,
    route: string,
    status: string,
    durationSeconds: number,
): void {
    if (!enabled) return;
    const labels = { method, route, status };
    httpRequests?.add(1, labels);
    httpDuration?.record(durationSeconds, labels);
}

// Side-effect bootstrap: MUST run before express/http are required so the
// auto-instrumentation (require-in-the-middle hooks) can patch them. index.ts
// imports this module first for exactly this reason.
initTelemetry();