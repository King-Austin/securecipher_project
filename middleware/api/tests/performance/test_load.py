# tests/system/test_load.py
import multiprocessing as mp
import statistics
from tabulate import tabulate
import pytest
import time

from .test_middleware_gateway import run_transaction


# ---------- Worker ---------- #
def worker_task(n: int, results_queue: mp.Queue):
    latencies = []
    errors = 0
    for _ in range(n):
        try:
            response, elapsed, _ = run_transaction(verbose=False)
            if response.status_code == 200:
                latencies.append(elapsed)
            else:
                errors += 1
        except Exception:
            errors += 1
    results_queue.put((latencies, errors))


# ---------- Load Test Runner ---------- #
def run_load(total_requests: int = 10, concurrency: int = 4):
    requests_per_worker = max(1, total_requests // concurrency)
    results_queue = mp.Queue()
    processes = []

    start_time = time.perf_counter()

    for _ in range(concurrency):
        p = mp.Process(target=worker_task, args=(requests_per_worker, results_queue))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    end_time = time.perf_counter()
    wall_time = end_time - start_time

    # Collect results
    all_latencies = []
    total_errors = 0
    while not results_queue.empty():
        latencies, errors = results_queue.get()
        all_latencies.extend(latencies)
        total_errors += errors

    if not all_latencies:
        print("⚠️ No successful transactions")
        return

    # Metrics
    avg_latency = statistics.mean(all_latencies)
    p95_latency = statistics.quantiles(all_latencies, n=100)[94] if len(all_latencies) >= 100 else max(all_latencies)
    throughput = len(all_latencies) / wall_time

    # Concise tabular output
    table = [[
        concurrency,
        total_requests,
        len(all_latencies),
        total_errors,
        round(avg_latency, 4),
        round(p95_latency, 4),
        round(throughput, 2)
    ]]
    headers = [
        "Concurrency", "Total Requests", "Successes", "Errors",
        "Avg Latency (s)", "p95 Latency (s)", "Throughput Txn/s"
    ]
    print("\n" + tabulate(table, headers=headers, tablefmt="grid"))


# ---------- Pytest Wrappers ---------- #
@pytest.mark.parametrize("total_requests, concurrency", [
    (1, 1),
    (100, 20),
])
def test_load(total_requests, concurrency):
    run_load(total_requests=total_requests, concurrency=concurrency)


# ---------- Optional Manual Run ---------- #
if __name__ == "__main__":
    run_load(total_requests=200, concurrency=10)
