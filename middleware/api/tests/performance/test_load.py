# load_test.py
import time
import statistics
import multiprocessing as mp
from test_middleware_gateway import run_transaction


def worker_task(n: int, results_queue: mp.Queue):
    latencies = []
    errors = 0
    for i in range(n):
        try:
            response, elapsed, decrypted = run_transaction()


            # Debug first few results per worker
            if i < 2:
                print(f"[DEBUG] Worker got {response.status_code}, body={response.text[:100]}")

            if response.status_code == 200:
                latencies.append(elapsed)
            else:
                errors += 1
        except Exception as e:
            errors += 1
            print(f"[ERROR] Exception in worker: {e}")

    results_queue.put((latencies, errors))


def run_load(total_requests: int = 5, concurrency: int = 4):
    requests_per_worker = max(1, total_requests // concurrency)
    results_queue = mp.Queue()
    processes = []

    for _ in range(concurrency):
        p = mp.Process(target=worker_task, args=(requests_per_worker, results_queue))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    # Gather results
    all_latencies = []
    total_errors = 0
    while not results_queue.empty():
        latencies, errors = results_queue.get()
        all_latencies.extend(latencies)
        total_errors += errors

    if not all_latencies:
        print("⚠️ No successful transactions")
        return

    # Stats
    avg_latency = statistics.mean(all_latencies)
    p95 = statistics.quantiles(all_latencies, n=100)[94] if len(all_latencies) >= 100 else max(all_latencies)
    throughput = len(all_latencies) / sum(all_latencies)  # req/sec approx

    print(f"Total Requests: {len(all_latencies) + total_errors}")
    print(f"Successes: {len(all_latencies)}")
    print(f"Errors: {total_errors}")
    print(f"Average latency: {avg_latency:.4f}s")
    print(f"95th percentile latency: {p95:.4f}s")
    print(f"Throughput: {throughput:.2f} req/s")


if __name__ == "__main__":
    run_load(total_requests=1, concurrency=1)
