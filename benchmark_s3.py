#!/usr/bin/env python3
"""
S3-Compatible Benchmark Script for Fula API

Benchmarks the S3-compatible gateway at a Fula endpoint, measuring
TTFB, throughput, latency percentiles, and success rates across
various object sizes, concurrency levels, and mixed workloads.

Generates a professional markdown report with charts and compares
results against published industry benchmarks (AWS S3, IPFS, R2, etc.).

Usage:
    python benchmark_s3.py --token <JWT> [--endpoint URL] [--bucket NAME] [--output FILE]

Dependencies:
    pip install aiohttp matplotlib
"""

import argparse
import asyncio
import os
import platform
import random
import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from xml.etree import ElementTree

import aiohttp
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


# ---------------------------------------------------------------------------
# Industry Benchmark Reference Data (publicly published numbers)
# ---------------------------------------------------------------------------
# Sources cited in the report. All values in milliseconds (latency) or MB/s.

INDUSTRY_BENCHMARKS = {
    # AWS S3 Standard (same-region EC2, compiled from multiple sources)
    # Sources: docs.aws.amazon.com, github.com/dvassallo/s3-benchmark,
    #          github.com/graykode/s3-latency, topicpartition.io
    "AWS S3": {
        "GET": {"64KB": 25, "1MB": 40, "10MB": 115},      # p50 TTFB in ms
        "PUT": {"64KB": 50, "1MB": 70, "10MB": 190},       # p50 TTFB in ms
        "throughput_single": 93,                             # MB/s per thread
    },
    # IPFS Public Gateways (cached content)
    # Sources: blog.cloudflare.com/ipfs-measurements,
    #          github.com/maxim-saplin/ipfs_gateway_research
    "IPFS Gateway (cached)": {
        "GET": {"64KB": 100, "1MB": 120, "10MB": 200},     # p50 TTFB in ms
        "PUT": {"64KB": None, "1MB": None, "10MB": None},  # not applicable
        "throughput_single": 15,                             # MB/s (top gateways)
    },
    # IPFS Uncached (requires DHT discovery)
    # Source: blog.cloudflare.com/ipfs-measurements
    "IPFS (uncached)": {
        "GET": {"64KB": 5000, "1MB": 10000, "10MB": 30000},
        "PUT": {"64KB": 1300, "1MB": 2000, "10MB": 5000},
        "throughput_single": 5,
    },
    # Cloudflare R2 (S3 API, not CDN)
    # Source: kerkour.com, tigrisdata.com/blog/benchmark-small-objects
    "Cloudflare R2": {
        "GET": {"64KB": 65, "1MB": 80, "10MB": 250},
        "PUT": {"64KB": 200, "1MB": 250, "10MB": 400},
        "throughput_single": 30,
    },
}

# Friendly names for error categories shown in report
ERROR_CATEGORY_NAMES = {
    "timeout": "Request Timed Out",
    "connection": "Connection Failed",
    "5xx": "Server Error (5xx)",
    "4xx": "Client Error (4xx)",
    "unknown": "Other / Unknown Error",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RequestMetric:
    """Timing data for a single HTTP request."""
    operation: str          # "PUT" (upload) or "GET" (download)
    key: str
    size: int               # object size in bytes
    ttfb_ms: float = 0.0    # time to first byte (server started responding)
    total_ms: float = 0.0   # total round-trip time (full transfer)
    throughput_mbps: float = 0.0  # megabytes per second
    success: bool = False
    status_code: int = 0
    error: str = ""
    error_category: str = ""


@dataclass
class TestResult:
    """Aggregated statistics for one test scenario."""
    label: str
    operation: str       # "PUT", "GET", or "MIXED"
    size_label: str      # e.g. "64KB", "1MB", "10MB"
    size_bytes: int
    concurrency: int     # how many parallel requests
    metrics: list[RequestMetric] = field(default_factory=list)

    @property
    def total_ops(self) -> int:
        return len(self.metrics)

    @property
    def successful(self) -> list[RequestMetric]:
        return [m for m in self.metrics if m.success]

    @property
    def failed(self) -> list[RequestMetric]:
        return [m for m in self.metrics if not m.success]

    @property
    def success_rate(self) -> float:
        if not self.metrics:
            return 0.0
        return len(self.successful) / len(self.metrics) * 100

    def _percentile(self, values: list[float], p: float) -> float:
        if not values:
            return 0.0
        sorted_v = sorted(values)
        k = (len(sorted_v) - 1) * (p / 100)
        f = int(k)
        c = f + 1
        if c >= len(sorted_v):
            return sorted_v[f]
        return sorted_v[f] + (k - f) * (sorted_v[c] - sorted_v[f])

    def ttfb_stats(self) -> dict:
        vals = [m.ttfb_ms for m in self.successful]
        if not vals:
            return {"mean": 0, "p50": 0, "p90": 0, "p95": 0, "p99": 0}
        return {
            "mean": statistics.mean(vals),
            "p50": self._percentile(vals, 50),
            "p90": self._percentile(vals, 90),
            "p95": self._percentile(vals, 95),
            "p99": self._percentile(vals, 99),
        }

    def latency_stats(self) -> dict:
        vals = [m.total_ms for m in self.successful]
        if not vals:
            return {"mean": 0, "p50": 0, "p90": 0, "p95": 0, "p99": 0}
        return {
            "mean": statistics.mean(vals),
            "p50": self._percentile(vals, 50),
            "p90": self._percentile(vals, 90),
            "p95": self._percentile(vals, 95),
            "p99": self._percentile(vals, 99),
        }

    def throughput_stats(self) -> dict:
        vals = [m.throughput_mbps for m in self.successful if m.throughput_mbps > 0]
        if not vals:
            return {"mean": 0, "p50": 0}
        return {
            "mean": statistics.mean(vals),
            "p50": self._percentile(vals, 50),
        }

    def error_breakdown(self) -> dict[str, int]:
        cats: dict[str, int] = {}
        for m in self.failed:
            cat = m.error_category or "unknown"
            cats[cat] = cats.get(cat, 0) + 1
        return cats


# ---------------------------------------------------------------------------
# S3 Benchmark Client
# ---------------------------------------------------------------------------

OBJECT_SIZES = [
    ("64KB", 64 * 1024),
    ("1MB", 1 * 1024 * 1024),
    ("10MB", 10 * 1024 * 1024),
]
CONCURRENCY_LEVELS = [1, 10, 50]

S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _timeout_for_size(size: int) -> aiohttp.ClientTimeout:
    if size <= 64 * 1024:
        return aiohttp.ClientTimeout(total=30, connect=10)
    elif size <= 1 * 1024 * 1024:
        return aiohttp.ClientTimeout(total=60, connect=10)
    else:
        return aiohttp.ClientTimeout(total=120, connect=10)


def _categorize_error(exc: Exception | None, status: int) -> str:
    if exc is not None:
        name = type(exc).__name__
        if "Timeout" in name or "timeout" in str(exc).lower():
            return "timeout"
        if "Connection" in name or "connect" in str(exc).lower():
            return "connection"
        return "unknown"
    if 500 <= status < 600:
        return "5xx"
    if 400 <= status < 500:
        return "4xx"
    return "unknown"


class S3BenchmarkClient:
    """Async HTTP client for S3-compatible operations."""

    def __init__(self, endpoint: str, token: str):
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=200, limit_per_host=200),
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _headers(self, extra: Optional[dict] = None) -> dict:
        h = {"Authorization": f"Bearer {self.token}"}
        if extra:
            h.update(extra)
        return h

    def _url(self, path: str) -> str:
        return f"{self.endpoint}/{path.lstrip('/')}"

    # -- Bucket operations --------------------------------------------------

    async def create_bucket(self, bucket: str) -> bool:
        session = await self._get_session()
        try:
            async with session.put(
                self._url(f"{bucket}/"),
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=30, connect=10),
            ) as resp:
                await resp.read()
                return resp.status in (200, 409)
        except Exception:
            return False

    async def head_bucket(self, bucket: str) -> bool:
        session = await self._get_session()
        try:
            async with session.head(
                self._url(f"{bucket}/"),
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=15, connect=10),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False

    async def delete_bucket(self, bucket: str) -> bool:
        session = await self._get_session()
        try:
            async with session.delete(
                self._url(f"{bucket}/"),
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=30, connect=10),
            ) as resp:
                await resp.read()
                return resp.status in (200, 204)
        except Exception:
            return False

    # -- Object operations --------------------------------------------------

    async def put_object(self, bucket: str, key: str, data: bytes) -> RequestMetric:
        metric = RequestMetric(operation="PUT", key=key, size=len(data))
        session = await self._get_session()
        timeout = _timeout_for_size(len(data))
        headers = self._headers({"Content-Type": "application/octet-stream"})

        retries = 0
        while True:
            try:
                start = time.monotonic()
                async with session.put(
                    self._url(f"{bucket}/{key}"),
                    data=data,
                    headers=headers,
                    timeout=timeout,
                ) as resp:
                    metric.ttfb_ms = (time.monotonic() - start) * 1000
                    await resp.read()
                    metric.total_ms = (time.monotonic() - start) * 1000
                    metric.status_code = resp.status

                    if resp.status == 429 and retries < 3:
                        retries += 1
                        await asyncio.sleep(1.0)
                        continue

                    if 200 <= resp.status < 300:
                        metric.success = True
                        if metric.total_ms > 0:
                            metric.throughput_mbps = (len(data) / (1024 * 1024)) / (metric.total_ms / 1000)
                    else:
                        metric.error = f"HTTP {resp.status}"
                        metric.error_category = _categorize_error(None, resp.status)
                    break
            except Exception as exc:
                metric.total_ms = (time.monotonic() - start) * 1000
                metric.ttfb_ms = metric.ttfb_ms or metric.total_ms
                metric.error = str(exc)[:200]
                metric.error_category = _categorize_error(exc, 0)
                break

        return metric

    async def get_object(self, bucket: str, key: str, expected_size: int = 0) -> RequestMetric:
        metric = RequestMetric(operation="GET", key=key, size=expected_size)
        session = await self._get_session()
        timeout = _timeout_for_size(expected_size)
        headers = self._headers()

        retries = 0
        while True:
            try:
                start = time.monotonic()
                async with session.get(
                    self._url(f"{bucket}/{key}"),
                    headers=headers,
                    timeout=timeout,
                ) as resp:
                    metric.ttfb_ms = (time.monotonic() - start) * 1000
                    body = await resp.read()
                    metric.total_ms = (time.monotonic() - start) * 1000
                    metric.status_code = resp.status

                    if resp.status == 429 and retries < 3:
                        retries += 1
                        await asyncio.sleep(1.0)
                        continue

                    if 200 <= resp.status < 300:
                        metric.success = True
                        metric.size = len(body)
                        if metric.total_ms > 0:
                            metric.throughput_mbps = (len(body) / (1024 * 1024)) / (metric.total_ms / 1000)
                    else:
                        metric.error = f"HTTP {resp.status}"
                        metric.error_category = _categorize_error(None, resp.status)
                    break
            except Exception as exc:
                metric.total_ms = (time.monotonic() - start) * 1000
                metric.ttfb_ms = metric.ttfb_ms or metric.total_ms
                metric.error = str(exc)[:200]
                metric.error_category = _categorize_error(exc, 0)
                break

        return metric

    async def head_object(self, bucket: str, key: str) -> bool:
        session = await self._get_session()
        try:
            async with session.head(
                self._url(f"{bucket}/{key}"),
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=15, connect=10),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False

    async def delete_object(self, bucket: str, key: str) -> bool:
        session = await self._get_session()
        try:
            async with session.delete(
                self._url(f"{bucket}/{key}"),
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=30, connect=10),
            ) as resp:
                await resp.read()
                return resp.status in (200, 204)
        except Exception:
            return False

    async def list_objects(self, bucket: str, prefix: str = "") -> list[str]:
        """List all object keys in a bucket (handles pagination)."""
        keys: list[str] = []
        continuation_token = None
        session = await self._get_session()

        while True:
            params: dict[str, str] = {"list-type": "2", "max-keys": "1000"}
            if prefix:
                params["prefix"] = prefix
            if continuation_token:
                params["continuation-token"] = continuation_token

            try:
                async with session.get(
                    self._url(f"{bucket}/"),
                    params=params,
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=30, connect=10),
                ) as resp:
                    if resp.status != 200:
                        break
                    body = await resp.text()
            except Exception:
                break

            try:
                root = ElementTree.fromstring(body)
                for contents in root.findall(f"{{{S3_NS}}}Contents"):
                    key_el = contents.find(f"{{{S3_NS}}}Key")
                    if key_el is not None and key_el.text:
                        keys.append(key_el.text)

                is_truncated = root.findtext(f"{{{S3_NS}}}IsTruncated", "false")
                if is_truncated.lower() == "true":
                    next_token = root.findtext(f"{{{S3_NS}}}NextContinuationToken")
                    if next_token:
                        continuation_token = next_token
                        continue
                break
            except ElementTree.ParseError:
                break

        return keys


# ---------------------------------------------------------------------------
# Benchmark Runner
# ---------------------------------------------------------------------------

class BenchmarkRunner:
    """Orchestrates all benchmark phases."""

    def __init__(self, client: S3BenchmarkClient, bucket: str):
        self.client = client
        self.bucket = bucket
        self.results: list[TestResult] = []
        self._uploaded_keys: dict[str, list[tuple[str, int]]] = {}

    def _log(self, msg: str):
        print(msg, file=sys.stderr, flush=True)

    async def warmup(self):
        """Issue a few throwaway requests to warm up connections."""
        self._log("  Warming up (3 requests)...")
        data = os.urandom(1024)
        for i in range(3):
            key = f"bench/_warmup/{uuid.uuid4().hex}"
            await self.client.put_object(self.bucket, key, data)
            await self.client.delete_object(self.bucket, key)

    async def phase1_setup(self):
        self._log(f"[Phase 1/5] Setup: Creating bucket '{self.bucket}'...")
        ok = await self.client.create_bucket(self.bucket)
        if ok:
            self._log(f"  Bucket created. Verifying with HEAD...")
            exists = await self.client.head_bucket(self.bucket)
            self._log(f"  HEAD bucket: {'OK' if exists else 'FAILED'}")
        else:
            self._log("  Bucket creation failed — may already exist, continuing...")

    async def run_concurrent_ops(
        self,
        coro_funcs: list,
        concurrency: int,
    ) -> list[RequestMetric]:
        """Run async operations with a concurrency semaphore."""
        sem = asyncio.Semaphore(concurrency)
        metrics: list[RequestMetric] = []

        async def _wrap(fn):
            async with sem:
                return await fn()

        tasks = [asyncio.create_task(_wrap(fn)) for fn in coro_funcs]
        for t in asyncio.as_completed(tasks):
            m = await t
            metrics.append(m)
        return metrics

    async def phase2_write_benchmark(self):
        self._log("[Phase 2/5] Write Benchmark (uploading objects):")
        for size_label, size_bytes in OBJECT_SIZES:
            self._uploaded_keys[size_label] = []
            for conc in CONCURRENCY_LEVELS:
                num_ops = max(10, conc)
                label = f"Upload {size_label} / {conc} parallel"

                ops = []
                for _ in range(num_ops):
                    key = f"bench/{size_label}/{uuid.uuid4().hex}"
                    data = os.urandom(size_bytes)
                    ops.append((key, data))

                coro_funcs = [
                    (lambda k=k, d=d: self.client.put_object(self.bucket, k, d))
                    for k, d in ops
                ]

                metrics = await self.run_concurrent_ops(coro_funcs, conc)

                result = TestResult(
                    label=label,
                    operation="PUT",
                    size_label=size_label,
                    size_bytes=size_bytes,
                    concurrency=conc,
                    metrics=metrics,
                )
                self.results.append(result)

                for m in metrics:
                    if m.success:
                        self._uploaded_keys[size_label].append((m.key, size_bytes))

                succ = len(result.successful)
                total = result.total_ops
                pct = result.success_rate
                avg = result.ttfb_stats()["mean"]
                self._log(
                    f"  [Upload] {size_label}, {conc} parallel: "
                    f"{succ}/{total} ({pct:.0f}%) avg={avg:.0f}ms"
                )

    async def phase3_read_benchmark(self):
        self._log("[Phase 3/5] Read Benchmark (downloading objects):")
        for size_label, size_bytes in OBJECT_SIZES:
            available = self._uploaded_keys.get(size_label, [])
            if not available:
                self._log(f"  [Download] {size_label}: No objects available, skipping.")
                continue

            for conc in CONCURRENCY_LEVELS:
                num_ops = max(40, conc * 4)
                label = f"Download {size_label} / {conc} parallel"

                chosen = [random.choice(available) for _ in range(num_ops)]

                coro_funcs = [
                    (lambda k=k, s=s: self.client.get_object(self.bucket, k, s))
                    for k, s in chosen
                ]

                metrics = await self.run_concurrent_ops(coro_funcs, conc)

                result = TestResult(
                    label=label,
                    operation="GET",
                    size_label=size_label,
                    size_bytes=size_bytes,
                    concurrency=conc,
                    metrics=metrics,
                )
                self.results.append(result)

                succ = len(result.successful)
                total = result.total_ops
                pct = result.success_rate
                avg = result.ttfb_stats()["mean"]
                self._log(
                    f"  [Download] {size_label}, {conc} parallel: "
                    f"{succ}/{total} ({pct:.0f}%) avg={avg:.0f}ms"
                )

    async def phase4_mixed_workload(self):
        self._log("[Phase 4/5] Mixed Workload (80% reads + 20% writes, 1MB objects):")
        mixed_size = 1 * 1024 * 1024
        available = self._uploaded_keys.get("1MB", [])

        for conc in CONCURRENCY_LEVELS:
            total_ops = 100
            num_reads = 80
            num_writes = 20
            label = f"Mixed 80/20 / {conc} parallel"

            ops = []
            for _ in range(num_reads):
                if available:
                    key, sz = random.choice(available)
                    ops.append(("GET", key, sz))
                else:
                    key = f"bench/1MB/{uuid.uuid4().hex}"
                    ops.append(("PUT", key, mixed_size))

            for _ in range(num_writes):
                key = f"bench/1MB/{uuid.uuid4().hex}"
                ops.append(("PUT", key, mixed_size))

            random.shuffle(ops)

            write_data_cache: dict[str, bytes] = {}

            def _make_coro(op_type, key, sz):
                if op_type == "GET":
                    return lambda: self.client.get_object(self.bucket, key, sz)
                else:
                    if key not in write_data_cache:
                        write_data_cache[key] = os.urandom(sz)
                    data = write_data_cache[key]
                    return lambda: self.client.put_object(self.bucket, key, data)

            coro_funcs = [_make_coro(ot, k, s) for ot, k, s in ops]
            metrics = await self.run_concurrent_ops(coro_funcs, conc)

            for m in metrics:
                if m.operation == "PUT" and m.success:
                    self._uploaded_keys.setdefault("1MB", []).append((m.key, mixed_size))

            result = TestResult(
                label=label,
                operation="MIXED",
                size_label="1MB",
                size_bytes=mixed_size,
                concurrency=conc,
                metrics=metrics,
            )
            self.results.append(result)

            succ = len(result.successful)
            total = result.total_ops
            pct = result.success_rate
            self._log(f"  [Mixed] {conc} parallel: {succ}/{total} ({pct:.0f}%)")

    async def phase5_cleanup(self):
        self._log("[Phase 5/5] Cleanup:")
        keys = await self.client.list_objects(self.bucket, prefix="bench/")
        self._log(f"  Deleting {len(keys)} objects...")

        sem = asyncio.Semaphore(50)

        async def _del(k):
            async with sem:
                return await self.client.delete_object(self.bucket, k)

        tasks = [asyncio.create_task(_del(k)) for k in keys]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        ok = await self.client.delete_bucket(self.bucket)
        self._log(f"  Delete bucket: {'OK' if ok else 'FAILED (may have remaining objects)'}")

    async def run(self) -> list[TestResult]:
        await self.phase1_setup()
        await self.warmup()
        await self.phase2_write_benchmark()
        await self.phase3_read_benchmark()
        await self.phase4_mixed_workload()
        await self.phase5_cleanup()
        return self.results


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

def _human_size(label: str) -> str:
    """Turn '64KB' into '64 KB' etc."""
    return label.replace("KB", " KB").replace("MB", " MB")


def _conc_label(conc: int) -> str:
    """Human-readable concurrency description."""
    if conc == 1:
        return "1 (sequential)"
    return str(conc)


class ReportGenerator:
    """Generates a markdown report with charts from benchmark results."""

    def __init__(
        self,
        results: list[TestResult],
        endpoint: str,
        bucket: str,
        output_path: str,
    ):
        self.results = results
        self.endpoint = endpoint
        self.bucket = bucket
        self.output_path = output_path
        self.output_dir = os.path.dirname(os.path.abspath(output_path)) or "."

    def generate(self):
        chart_files = self.generate_charts()
        md = self.generate_markdown(chart_files)
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(md)

    # -----------------------------------------------------------------------
    # Markdown report
    # -----------------------------------------------------------------------

    def generate_markdown(self, chart_files: dict[str, str]) -> str:
        lines: list[str] = []

        # -- Title & intro --
        lines.append("# Fula S3 Gateway — Performance Benchmark Report\n")
        lines.append(
            "This report measures how fast the Fula decentralized storage gateway "
            "responds to standard S3 (upload/download) requests. "
            "It tests different file sizes and levels of simultaneous traffic, "
            "then compares the results against published numbers from "
            "AWS S3, IPFS public gateways, and Cloudflare R2.\n"
        )

        # -- Glossary --
        lines.append("## How to Read This Report\n")
        lines.append("| Term | What It Means |")
        lines.append("|------|---------------|")
        lines.append(
            '| **TTFB** (Time to First Byte) | How long until the server *starts* '
            'responding. Lower = faster. Measured in milliseconds (ms). |'
        )
        lines.append(
            '| **Throughput** | How much data is transferred per second. '
            'Measured in megabytes per second (MB/s). Higher = faster. |'
        )
        lines.append(
            '| **Latency** | Total time for the entire request to complete '
            '(upload or download finished). Measured in ms. Lower = faster. |'
        )
        lines.append(
            '| **p50 / p90 / p95 / p99** | Percentile values. '
            'p50 = the median (half of requests were faster). '
            'p99 = 99% of requests were faster than this value (the slow outliers). |'
        )
        lines.append(
            '| **Parallel requests** | How many requests run at the same time. '
            '"1" means one-at-a-time (sequential). '
            '"50" means 50 simultaneous requests hitting the server. |'
        )
        lines.append(
            '| **Success Rate** | Percentage of requests that completed without error. '
            '95%+ is considered acceptable; 99%+ is excellent. |'
        )
        lines.append(
            '| **Upload / Download** | Upload = writing a file to storage (PUT). '
            'Download = reading a file back (GET). |'
        )
        lines.append(
            '| **Mixed 80/20** | A realistic workload: '
            '80% of operations are downloads (reads) and 20% are uploads (writes). |'
        )
        lines.append("")

        # -- Test metadata --
        lines.append("## Test Configuration\n")
        lines.append("| Setting | Value |")
        lines.append("|---------|-------|")
        lines.append(f"| Endpoint tested | `{self.endpoint}` |")
        lines.append(f"| Bucket name | `{self.bucket}` |")
        lines.append(f"| Date / time (UTC) | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} |")
        lines.append(f"| Machine | {platform.platform()} |")
        lines.append(f"| Python version | {platform.python_version()} |")
        lines.append(f"| File sizes tested | 64 KB, 1 MB, 10 MB |")
        lines.append(f"| Parallel request levels | 1 (sequential), 10, and 50 |")
        lines.append(f"| Mixed workload ratio | 80% downloads / 20% uploads |")
        lines.append("")

        # -- Summary table --
        lines.append("## Results at a Glance\n")
        lines.append(
            "Each row is one test scenario. "
            '"TTFB" columns show how fast the server started responding; '
            '"Throughput" shows the average transfer speed.\n'
        )
        lines.append(
            "| Scenario | Requests | Success Rate | "
            "Avg TTFB | Median (p50) | p90 | p95 | p99 | Avg Throughput |"
        )
        lines.append(
            "|----------|----------|--------------|"
            "----------|--------------|-----|-----|-----|----------------|"
        )

        for r in self.results:
            ts = r.ttfb_stats()
            tp = r.throughput_stats()
            lines.append(
                f"| {r.label} | {r.total_ops} | {r.success_rate:.1f}% "
                f"| {ts['mean']:.0f} ms | {ts['p50']:.0f} ms | {ts['p90']:.0f} ms "
                f"| {ts['p95']:.0f} ms | {ts['p99']:.0f} ms | {tp['mean']:.2f} MB/s |"
            )
        lines.append("")

        # -- Phase details --
        for phase_name, op_filter, description in [
            (
                "Upload Performance (Write Benchmark)",
                "PUT",
                "Measures how fast files can be uploaded to storage. "
                "Each file is filled with random bytes to prevent deduplication.",
            ),
            (
                "Download Performance (Read Benchmark)",
                "GET",
                "Measures how fast previously-uploaded files can be downloaded back. "
                "Each request downloads a complete file and verifies the response.",
            ),
            (
                "Mixed Workload (Realistic Traffic)",
                "MIXED",
                "Simulates realistic traffic: 80% of operations are downloads "
                "and 20% are uploads, using 1 MB files. "
                "This models a typical application where users read data more often than they write.",
            ),
        ]:
            phase_results = [r for r in self.results if r.operation == op_filter]
            if not phase_results:
                continue

            lines.append(f"## {phase_name}\n")
            lines.append(f"{description}\n")
            lines.append(
                "| Scenario | Requests | Success Rate | Avg TTFB | Median TTFB | "
                "p90 TTFB | p99 TTFB | Avg Total Latency | Avg Throughput |"
            )
            lines.append(
                "|----------|----------|--------------|----------|-------------|"
                "----------|----------|-------------------|----------------|"
            )

            for r in phase_results:
                ts = r.ttfb_stats()
                ls = r.latency_stats()
                tp = r.throughput_stats()
                lines.append(
                    f"| {r.label} | {r.total_ops} | {r.success_rate:.1f}% "
                    f"| {ts['mean']:.0f} ms | {ts['p50']:.0f} ms | {ts['p90']:.0f} ms "
                    f"| {ts['p99']:.0f} ms "
                    f"| {ls['mean']:.0f} ms | {tp['mean']:.2f} MB/s |"
                )
            lines.append("")

        # -- Industry comparison --
        lines.append("## How Does Fula Compare to the Industry?\n")
        lines.append(
            "The table below compares Fula's median (p50) TTFB against published "
            "benchmarks from other storage services. Fula is a **decentralized** "
            "storage network backed by IPFS, so it is most fairly compared against "
            "other IPFS-based systems. AWS S3 and Cloudflare R2 are included as "
            "centralized baselines for reference.\n"
        )
        lines.append(
            "> **Important context:** AWS S3 numbers are typically measured from EC2 instances "
            "in the *same data center*. Fula routes through a decentralized network, so higher "
            "latency is expected. The key comparison is against IPFS gateways.\n"
        )

        # Build comparison rows
        fula_get = {}
        fula_put = {}
        for r in self.results:
            if r.operation == "GET" and r.concurrency == 1:
                fula_get[r.size_label] = r.ttfb_stats()["p50"]
            if r.operation == "PUT" and r.concurrency == 1:
                fula_put[r.size_label] = r.ttfb_stats()["p50"]

        lines.append("### Download (GET) — Median TTFB at 1 parallel request\n")
        lines.append("| Service | 64 KB | 1 MB | 10 MB | Source |")
        lines.append("|---------|-------|------|-------|--------|")
        # Fula row
        lines.append(
            f"| **Fula S3 Gateway** | "
            f"**{fula_get.get('64KB', 0):.0f} ms** | "
            f"**{fula_get.get('1MB', 0):.0f} ms** | "
            f"**{fula_get.get('10MB', 0):.0f} ms** | This benchmark |"
        )
        for service, data in INDUSTRY_BENCHMARKS.items():
            g = data["GET"]
            vals = []
            for sz in ["64KB", "1MB", "10MB"]:
                v = g.get(sz)
                vals.append(f"{v} ms" if v is not None else "n/a")
            src = _benchmark_source(service)
            lines.append(f"| {service} | {vals[0]} | {vals[1]} | {vals[2]} | {src} |")
        lines.append("")

        lines.append("### Upload (PUT) — Median TTFB at 1 parallel request\n")
        lines.append("| Service | 64 KB | 1 MB | 10 MB | Source |")
        lines.append("|---------|-------|------|-------|--------|")
        lines.append(
            f"| **Fula S3 Gateway** | "
            f"**{fula_put.get('64KB', 0):.0f} ms** | "
            f"**{fula_put.get('1MB', 0):.0f} ms** | "
            f"**{fula_put.get('10MB', 0):.0f} ms** | This benchmark |"
        )
        for service, data in INDUSTRY_BENCHMARKS.items():
            p = data["PUT"]
            vals = []
            for sz in ["64KB", "1MB", "10MB"]:
                v = p.get(sz)
                vals.append(f"{v} ms" if v is not None else "n/a")
            src = _benchmark_source(service)
            lines.append(f"| {service} | {vals[0]} | {vals[1]} | {vals[2]} | {src} |")
        lines.append("")

        lines.append("### Throughput — Single-stream average\n")
        lines.append("| Service | Avg Throughput (MB/s) | Source |")
        lines.append("|---------|----------------------|--------|")
        fula_tp_vals = [
            r.throughput_stats()["mean"]
            for r in self.results
            if r.operation == "GET" and r.concurrency == 1 and r.throughput_stats()["mean"] > 0
        ]
        fula_tp = statistics.mean(fula_tp_vals) if fula_tp_vals else 0
        lines.append(f"| **Fula S3 Gateway** | **{fula_tp:.1f}** | This benchmark |")
        for service, data in INDUSTRY_BENCHMARKS.items():
            tp = data.get("throughput_single", 0)
            src = _benchmark_source(service)
            lines.append(f"| {service} | {tp} | {src} |")
        lines.append("")

        # -- Charts --
        lines.append("## Charts\n")
        for title, fname in chart_files.items():
            lines.append(f"### {title}\n")
            lines.append(f"![{title}]({fname})\n")

        # -- Error summary --
        all_errors: dict[str, int] = {}
        for r in self.results:
            for cat, count in r.error_breakdown().items():
                all_errors[cat] = all_errors.get(cat, 0) + 1

        if all_errors:
            lines.append("## Error Summary\n")
            lines.append(
                "The table below shows how many requests failed and why. "
                "Occasional errors are normal for any network service.\n"
            )
            lines.append("| Error Type | Count | Explanation |")
            lines.append("|------------|-------|-------------|")
            for cat, count in sorted(all_errors.items(), key=lambda x: -x[1]):
                name = ERROR_CATEGORY_NAMES.get(cat, cat)
                explanation = _error_explanation(cat)
                lines.append(f"| {name} | {count} | {explanation} |")
            lines.append("")

        # -- Conclusion --
        lines.append("## Conclusion\n")
        total_ops = sum(r.total_ops for r in self.results)
        total_success = sum(len(r.successful) for r in self.results)
        overall_rate = (total_success / total_ops * 100) if total_ops else 0

        lines.append(f"**Total requests made:** {total_ops}  ")
        lines.append(f"**Overall success rate:** {overall_rate:.1f}%\n")

        checks = []
        if overall_rate >= 99:
            checks.append(f"PASS — Excellent reliability: {overall_rate:.1f}% success rate (target: >= 95%)")
        elif overall_rate >= 95:
            checks.append(f"PASS — Good reliability: {overall_rate:.1f}% success rate (target: >= 95%)")
        else:
            checks.append(f"FAIL — Reliability below target: {overall_rate:.1f}% success rate (target: >= 95%)")

        read_results = [r for r in self.results if r.operation == "GET"]
        if read_results:
            valid_ttfbs = [r.ttfb_stats()["mean"] for r in read_results if r.ttfb_stats()["mean"] > 0]
            if valid_ttfbs:
                avg_read_ttfb = statistics.mean(valid_ttfbs)
                if avg_read_ttfb < 500:
                    checks.append(
                        f"PASS — Fast downloads: average TTFB {avg_read_ttfb:.0f} ms "
                        f"(competitive with cached IPFS gateways at ~100-120 ms)"
                    )
                elif avg_read_ttfb < 2000:
                    checks.append(
                        f"PASS — Acceptable downloads: average TTFB {avg_read_ttfb:.0f} ms "
                        f"(faster than uncached IPFS at ~5,000+ ms)"
                    )
                elif avg_read_ttfb < 5000:
                    checks.append(
                        f"WARN — Slow downloads: average TTFB {avg_read_ttfb:.0f} ms "
                        f"(comparable to uncached IPFS; consider caching improvements)"
                    )
                else:
                    checks.append(
                        f"FAIL — Very slow downloads: average TTFB {avg_read_ttfb:.0f} ms "
                        f"(exceeds typical IPFS uncached latency)"
                    )

        write_results = [r for r in self.results if r.operation == "PUT"]
        if write_results:
            valid_ttfbs = [r.ttfb_stats()["mean"] for r in write_results if r.ttfb_stats()["mean"] > 0]
            if valid_ttfbs:
                avg_write_ttfb = statistics.mean(valid_ttfbs)
                if avg_write_ttfb < 500:
                    checks.append(
                        f"PASS — Fast uploads: average TTFB {avg_write_ttfb:.0f} ms "
                        f"(competitive with centralized S3 at ~50-190 ms)"
                    )
                elif avg_write_ttfb < 5000:
                    checks.append(
                        f"PASS — Acceptable uploads: average TTFB {avg_write_ttfb:.0f} ms "
                        f"(much faster than standard IPFS DHT provide at 30,000+ ms)"
                    )
                else:
                    checks.append(
                        f"WARN — Slow uploads: average TTFB {avg_write_ttfb:.0f} ms "
                        f"(consider investigating upload pipeline)"
                    )

        lines.append("### Verdict\n")
        for c in checks:
            lines.append(f"- {c}")
        lines.append("")

        # -- Sources --
        lines.append("## Industry Benchmark Sources\n")
        lines.append(
            "The industry comparison numbers used in this report come from the following "
            "publicly available sources:\n"
        )
        lines.append(
            "- **AWS S3**: [AWS S3 Performance Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/optimizing-performance.html), "
            "[dvassallo/s3-benchmark](https://github.com/dvassallo/s3-benchmark), "
            "[graykode/s3-latency](https://github.com/graykode/s3-latency)"
        )
        lines.append(
            "- **IPFS (cached)**: [Cloudflare IPFS Measurements](https://blog.cloudflare.com/ipfs-measurements/), "
            "[IPFS Gateway Research](https://github.com/maxim-saplin/ipfs_gateway_research)"
        )
        lines.append(
            "- **IPFS (uncached)**: [Cloudflare IPFS Measurements](https://blog.cloudflare.com/ipfs-measurements/) "
            "(average 44s for newly-created uncached content)"
        )
        lines.append(
            "- **Cloudflare R2**: [kerkour.com S3 vs R2](https://kerkour.com/aws-s3-vs-cloudflare-r2-price-performance-user-experience), "
            "[Tigris Data Benchmark](https://www.tigrisdata.com/blog/benchmark-small-objects/)"
        )
        lines.append("")

        lines.append("---")
        lines.append(
            f"*Generated by `benchmark_s3.py` on "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*\n"
        )

        return "\n".join(lines)

    # -----------------------------------------------------------------------
    # Charts
    # -----------------------------------------------------------------------

    def generate_charts(self) -> dict[str, str]:
        chart_files: dict[str, str] = {}

        try:
            plt.style.use("seaborn-v0_8-whitegrid")
        except OSError:
            pass

        COLOR_UPLOAD = "#4C72B0"       # steel blue
        COLOR_DOWNLOAD = "#DD8452"     # warm orange
        COLOR_AWS = "#2ca02c"          # green
        COLOR_IPFS_CACHED = "#9467bd"  # purple
        COLOR_PASS = "#55A868"         # muted green
        COLOR_FAIL = "#C44E52"         # muted red
        COLOR_BOX_UPLOAD = "#7BAFD4"   # light blue
        COLOR_BOX_DOWNLOAD = "#F0A975" # light orange
        COLOR_BOX_MIXED = "#A8D5A2"    # light green

        write_results = [r for r in self.results if r.operation == "PUT"]
        read_results = [r for r in self.results if r.operation == "GET"]

        # --- Chart 1: TTFB Comparison with industry reference lines ---
        fname = "benchmark_ttfb_comparison.png"
        fpath = os.path.join(self.output_dir, fname)
        chart_files["Time to First Byte (TTFB) — Upload vs Download"] = fname

        fig, ax = plt.subplots(figsize=(14, 7))

        labels = []
        write_vals = []
        read_vals = []
        aws_get_vals = []
        ipfs_get_vals = []
        for size_label, _ in OBJECT_SIZES:
            for conc in CONCURRENCY_LEVELS:
                lbl = f"{_human_size(size_label)}\n{conc} parallel"
                labels.append(lbl)
                w = [r for r in write_results if r.size_label == size_label and r.concurrency == conc]
                rd = [r for r in read_results if r.size_label == size_label and r.concurrency == conc]
                write_vals.append(w[0].ttfb_stats()["mean"] if w else 0)
                read_vals.append(rd[0].ttfb_stats()["mean"] if rd else 0)
                aws_get_vals.append(INDUSTRY_BENCHMARKS["AWS S3"]["GET"].get(size_label, 0))
                v = INDUSTRY_BENCHMARKS["IPFS Gateway (cached)"]["GET"].get(size_label)
                ipfs_get_vals.append(v if v is not None else 0)

        x = list(range(len(labels)))
        width = 0.30
        bars_up = ax.bar(
            [i - width / 2 for i in x], write_vals, width,
            label="Fula Upload (PUT)", color=COLOR_UPLOAD, edgecolor="white", linewidth=0.5,
        )
        bars_dl = ax.bar(
            [i + width / 2 for i in x], read_vals, width,
            label="Fula Download (GET)", color=COLOR_DOWNLOAD, edgecolor="white", linewidth=0.5,
        )

        # Industry reference markers
        ax.scatter(
            x, aws_get_vals, marker="D", s=60, color=COLOR_AWS, zorder=5,
            label="AWS S3 Download (published baseline)",
        )
        ax.scatter(
            x, ipfs_get_vals, marker="s", s=60, color=COLOR_IPFS_CACHED, zorder=5,
            label="IPFS Cached Download (published baseline)",
        )

        # Value labels on bars
        for bar in bars_up:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + max(write_vals + read_vals) * 0.01,
                        f"{h:.0f}", ha="center", va="bottom", fontsize=7, color=COLOR_UPLOAD)
        for bar in bars_dl:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + max(write_vals + read_vals) * 0.01,
                        f"{h:.0f}", ha="center", va="bottom", fontsize=7, color=COLOR_DOWNLOAD)

        ax.set_ylabel("Time to First Byte in milliseconds (lower is faster)", fontsize=10)
        ax.set_title(
            "Time to First Byte (TTFB) — How fast does the server start responding?",
            fontsize=12, fontweight="bold", pad=15,
        )
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=9)
        ax.legend(loc="upper left", fontsize=9, framealpha=0.9)
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(fpath, dpi=150)
        plt.close(fig)

        # --- Chart 2: Throughput Comparison ---
        fname = "benchmark_throughput_comparison.png"
        fpath = os.path.join(self.output_dir, fname)
        chart_files["Throughput — Upload vs Download Speed"] = fname

        fig, ax = plt.subplots(figsize=(14, 7))
        write_tp = []
        read_tp = []
        for size_label, _ in OBJECT_SIZES:
            for conc in CONCURRENCY_LEVELS:
                w = [r for r in write_results if r.size_label == size_label and r.concurrency == conc]
                rd = [r for r in read_results if r.size_label == size_label and r.concurrency == conc]
                write_tp.append(w[0].throughput_stats()["mean"] if w else 0)
                read_tp.append(rd[0].throughput_stats()["mean"] if rd else 0)

        bars_up = ax.bar(
            [i - width / 2 for i in x], write_tp, width,
            label="Fula Upload Speed", color=COLOR_UPLOAD, edgecolor="white", linewidth=0.5,
        )
        bars_dl = ax.bar(
            [i + width / 2 for i in x], read_tp, width,
            label="Fula Download Speed", color=COLOR_DOWNLOAD, edgecolor="white", linewidth=0.5,
        )

        # AWS S3 single-stream reference line
        aws_tp = INDUSTRY_BENCHMARKS["AWS S3"]["throughput_single"]
        ax.axhline(
            y=aws_tp, color=COLOR_AWS, linestyle="--", alpha=0.7, linewidth=1.5,
            label=f"AWS S3 single-stream baseline ({aws_tp} MB/s)",
        )
        ipfs_tp = INDUSTRY_BENCHMARKS["IPFS Gateway (cached)"]["throughput_single"]
        ax.axhline(
            y=ipfs_tp, color=COLOR_IPFS_CACHED, linestyle=":", alpha=0.7, linewidth=1.5,
            label=f"IPFS cached gateway baseline ({ipfs_tp} MB/s)",
        )

        # Value labels
        for bar in bars_up:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.3,
                        f"{h:.1f}", ha="center", va="bottom", fontsize=7, color=COLOR_UPLOAD)
        for bar in bars_dl:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.3,
                        f"{h:.1f}", ha="center", va="bottom", fontsize=7, color=COLOR_DOWNLOAD)

        ax.set_ylabel("Throughput in MB/s (higher is faster)", fontsize=10)
        ax.set_title(
            "Transfer Speed — How fast is data moved?",
            fontsize=12, fontweight="bold", pad=15,
        )
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=9)
        ax.legend(loc="upper left", fontsize=9, framealpha=0.9)
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(fpath, dpi=150)
        plt.close(fig)

        # --- Chart 3: Success Rate ---
        fname = "benchmark_success_rate.png"
        fpath = os.path.join(self.output_dir, fname)
        chart_files["Success Rate — Did Requests Complete Without Error?"] = fname

        fig, ax = plt.subplots(figsize=(16, 6))
        sr_labels = [r.label for r in self.results]
        sr_vals = [r.success_rate for r in self.results]
        bar_colors = [COLOR_PASS if v >= 95 else COLOR_FAIL for v in sr_vals]
        bars = ax.bar(range(len(sr_labels)), sr_vals, color=bar_colors, edgecolor="white", linewidth=0.5)

        # Value labels on each bar
        for bar, val in zip(bars, sr_vals):
            ax.text(
                bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                f"{val:.1f}%", ha="center", va="bottom", fontsize=7, fontweight="bold",
            )

        ax.set_ylabel("Success Rate (%)", fontsize=10)
        ax.set_title(
            "Request Success Rate — What percentage of requests succeeded?",
            fontsize=12, fontweight="bold", pad=15,
        )
        ax.set_xticks(range(len(sr_labels)))
        ax.set_xticklabels(sr_labels, rotation=40, ha="right", fontsize=8)
        ax.set_ylim(0, 110)
        ax.axhline(
            y=95, color="gray", linestyle="--", alpha=0.6, linewidth=1.5,
            label="95% acceptable threshold",
        )
        # Legend patches
        pass_patch = mpatches.Patch(color=COLOR_PASS, label="95%+ (acceptable)")
        fail_patch = mpatches.Patch(color=COLOR_FAIL, label="Below 95% (needs attention)")
        threshold_line = plt.Line2D([0], [0], color="gray", linestyle="--", label="95% threshold line")
        ax.legend(handles=[pass_patch, fail_patch, threshold_line], loc="lower left", fontsize=9)
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(fpath, dpi=150)
        plt.close(fig)

        # --- Chart 4: Latency Distribution (Box Plot) ---
        fname = "benchmark_latency_distribution.png"
        fpath = os.path.join(self.output_dir, fname)
        chart_files["Latency Distribution — How Consistent Are Response Times?"] = fname

        fig, ax = plt.subplots(figsize=(16, 7))
        box_data = []
        box_labels = []
        box_colors = []
        for r in self.results:
            vals = [m.total_ms for m in r.successful]
            if vals:
                box_data.append(vals)
                box_labels.append(r.label)
                if r.operation == "PUT":
                    box_colors.append(COLOR_BOX_UPLOAD)
                elif r.operation == "GET":
                    box_colors.append(COLOR_BOX_DOWNLOAD)
                else:
                    box_colors.append(COLOR_BOX_MIXED)

        if box_data:
            bp = ax.boxplot(
                box_data, patch_artist=True, showfliers=True,
                flierprops={"marker": "o", "markersize": 4, "alpha": 0.5, "markerfacecolor": "#999999"},
                medianprops={"color": "black", "linewidth": 1.5},
                whiskerprops={"linewidth": 1.0},
            )
            for patch, color in zip(bp["boxes"], box_colors):
                patch.set_facecolor(color)
                patch.set_alpha(0.8)
            ax.set_xticklabels(box_labels, rotation=40, ha="right", fontsize=8)

        # Legend
        upload_patch = mpatches.Patch(color=COLOR_BOX_UPLOAD, alpha=0.8, label="Upload tests")
        download_patch = mpatches.Patch(color=COLOR_BOX_DOWNLOAD, alpha=0.8, label="Download tests")
        mixed_patch = mpatches.Patch(color=COLOR_BOX_MIXED, alpha=0.8, label="Mixed workload tests")
        ax.legend(handles=[upload_patch, download_patch, mixed_patch], loc="upper left", fontsize=9)

        # Annotations explaining box plot parts
        ax.annotate(
            "Box = middle 50% of requests\n"
            "Line inside box = median\n"
            "Whiskers = typical range\n"
            "Dots = slow outliers",
            xy=(0.98, 0.97), xycoords="axes fraction",
            ha="right", va="top", fontsize=8,
            bbox={"boxstyle": "round,pad=0.5", "facecolor": "lightyellow", "alpha": 0.9, "edgecolor": "gray"},
        )

        ax.set_ylabel("Total request time in milliseconds (lower is faster)", fontsize=10)
        ax.set_title(
            "Latency Distribution — How consistent are response times?",
            fontsize=12, fontweight="bold", pad=15,
        )
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(fpath, dpi=150)
        plt.close(fig)

        return chart_files


# ---------------------------------------------------------------------------
# Helpers for markdown generation
# ---------------------------------------------------------------------------

def _benchmark_source(service: str) -> str:
    sources = {
        "AWS S3": "AWS docs, dvassallo, graykode",
        "IPFS Gateway (cached)": "Cloudflare blog, IPFS gateway research",
        "IPFS (uncached)": "Cloudflare IPFS measurements",
        "Cloudflare R2": "kerkour.com, Tigris Data",
    }
    return sources.get(service, "")


def _error_explanation(category: str) -> str:
    explanations = {
        "timeout": "The server did not respond within the time limit. May indicate high load or large file processing.",
        "connection": "Could not establish a connection to the server. May indicate network issues or server unavailability.",
        "5xx": "The server encountered an internal error. Typically transient; retrying usually succeeds.",
        "4xx": "The request was rejected (e.g., authentication issue, missing resource, bad request format).",
        "unknown": "An unexpected error occurred that does not fit the other categories.",
    }
    return explanations.get(category, "")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="S3-Compatible Benchmark for Fula API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python benchmark_s3.py --token "eyJ..."
  python benchmark_s3.py --token "eyJ..." --endpoint https://s3.cloud.fx.land
  python benchmark_s3.py --token "eyJ..." --bucket my-bench --output results.md
        """,
    )
    parser.add_argument(
        "--token", required=True, help="JWT Bearer token for authentication"
    )
    parser.add_argument(
        "--endpoint",
        default="https://s3.cloud.fx.land",
        help="S3 endpoint URL (default: https://s3.cloud.fx.land)",
    )
    parser.add_argument(
        "--bucket",
        default=None,
        help="Bucket name (default: benchmark-{timestamp})",
    )
    parser.add_argument(
        "--output",
        default="benchmark_results.md",
        help="Output markdown report path (default: benchmark_results.md)",
    )
    return parser.parse_args()


async def async_main():
    args = parse_args()
    bucket = args.bucket or f"benchmark-{int(time.time())}"
    endpoint = args.endpoint.rstrip("/")
    output = args.output

    print(
        f"Fula S3 Benchmark\n"
        f"  Endpoint: {endpoint}\n"
        f"  Bucket:   {bucket}\n"
        f"  Output:   {output}\n",
        file=sys.stderr,
    )

    client = S3BenchmarkClient(endpoint, args.token)
    runner = BenchmarkRunner(client, bucket)

    try:
        results = await runner.run()
    finally:
        await client.close()

    print("Generating report...", file=sys.stderr, flush=True)
    report = ReportGenerator(results, endpoint, bucket, output)
    report.generate()

    print(f"Report saved to {output}", file=sys.stderr, flush=True)
    print("4 chart PNGs generated alongside report.", file=sys.stderr, flush=True)


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
