#!/usr/bin/env python3
import os
import re
import selectors
import shutil
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path


ITERATIONS = int(os.environ.get("ZT_BENCH_ITERATIONS", "1000000"))
BENCH_REPEATS = int(os.environ.get("ZT_BENCH_REPEATS", "5"))
LATENCY_ROUNDS = int(os.environ.get("ZT_BENCH_LATENCY_ROUNDS", "1000"))
NSEC_PER_MSEC = 1_000_000.0
ZTRACE_RUNNER_TIMEOUT_SEC = 20.0
ROOT_DIR = Path(__file__).resolve().parent.parent
TARGET = ROOT_DIR / "bin" / "tests" / "test_benchmark_target"
BENCH_RUNNER = ROOT_DIR / "bin" / "tests" / "test_benchmark_runner"
LATENCY_RUNNER = ROOT_DIR / "bin" / "tests" / "test_benchmark_latency"
RESULT_DIR = ROOT_DIR / "benchmark"
BASELINE_OUT = RESULT_DIR / "baseline.out"
UPROBE_OUT = RESULT_DIR / "uprobe.out"
UPROBE_TRACE_OUT = RESULT_DIR / "uprobe.bpftrace.out"
ZTRACE_OUT = RESULT_DIR / "ztrace.out"
ZTRACE_RUNNER_OUT = RESULT_DIR / "ztrace.runner.out"
ZTRACE_LOG_OUT = RESULT_DIR / "ztrace.benchmark.log"
LATENCY_OUT = RESULT_DIR / "latency.out"
REPORT_OUT = RESULT_DIR / "report.txt"
RESULT_FILES = [
    BASELINE_OUT,
    UPROBE_OUT,
    UPROBE_TRACE_OUT,
    ZTRACE_OUT,
    ZTRACE_RUNNER_OUT,
    ZTRACE_LOG_OUT,
    LATENCY_OUT,
    REPORT_OUT,
]


def write_text(path: Path, data: str) -> None:
    path.write_text(data, encoding="utf-8")


def append_round_output(path: Path, round_index: int, data: str) -> None:
    with path.open("a", encoding="utf-8") as fp:
        fp.write(f"=== round {round_index} ===\n")
        fp.write(data)
        if not data.endswith("\n"):
            fp.write("\n")


def mean_value(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


def stdev_value(values: list[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def format_stats_block(prefix: str,
                       mean_text: str,
                       min_text: str,
                       max_text: str,
                       stdev_text: str,
                       unit: str = "") -> str:
    suffix = f" {unit}" if unit else ""

    return (
        f"{prefix} mean : {mean_text}{suffix}\n"
        f"{prefix} min  : {min_text}{suffix}\n"
        f"{prefix} max  : {max_text}{suffix}\n"
        f"{prefix} stdev: {stdev_text}{suffix}\n"
    )


def format_float_stats(prefix: str, values: list[float], unit: str = "") -> str:
    return format_stats_block(prefix,
                              f"{mean_value(values):.2f}",
                              f"{min(values):.2f}",
                              f"{max(values):.2f}",
                              f"{stdev_value(values):.2f}",
                              unit)


def format_int_stats(prefix: str, values: list[int], unit: str = "") -> str:
    float_values = [float(v) for v in values]

    return format_stats_block(prefix,
                              f"{mean_value(float_values):.0f}",
                              f"{min(values)}",
                              f"{max(values)}",
                              f"{stdev_value(float_values):.0f}",
                              unit)


def find_uprobe_events_path() -> Path | None:
    for candidate in (
        Path("/sys/kernel/tracing/uprobe_events"),
        Path("/sys/kernel/debug/tracing/uprobe_events"),
    ):
        proc = subprocess.run(
            ["sudo", "-n", "test", "-e", str(candidate)],
            cwd=ROOT_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if proc.returncode == 0:
            return candidate
    return None


def extract_total_ns(text: str) -> int:
    match = re.search(r"\btotal_ns=(\d+)\b", text)
    if match is None:
        raise RuntimeError(f"failed to parse total_ns from output:\n{text}")
    return int(match.group(1))


def extract_latency_ns(text: str) -> tuple[int, int]:
    install = re.search(r"\binstall_ns=(\d+)\b", text)
    uninstall = re.search(r"\buninstall_ns=(\d+)\b", text)
    if install is None or uninstall is None:
        raise RuntimeError(f"failed to parse latency metrics from output:\n{text}")
    return int(install.group(1)), int(uninstall.group(1))


def extract_bpftrace_count(text: str) -> int:
    match = re.search(r"@n:\s*(\d+)", text)
    if match is None:
        raise RuntimeError(f"failed to parse bpftrace count from output:\n{text}")
    return int(match.group(1))


def run_and_capture(cmd, env=None) -> str:
    proc = subprocess.run(
        cmd,
        cwd=ROOT_DIR,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.stdout


def start_waiting_target() -> subprocess.Popen:
    env = os.environ.copy()
    env["ZT_BENCH_WAIT_SIGUSR1"] = "1"

    return subprocess.Popen(
        [str(TARGET), str(ITERATIONS)],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def wait_for_target_result(proc: subprocess.Popen, timeout: float = 120.0) -> str:
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        raise RuntimeError(f"benchmark target timed out:\n{out}")

    if proc.returncode != 0:
        raise RuntimeError(f"benchmark target failed with code {proc.returncode}:\n{out}")

    return out


def stop_process(proc: subprocess.Popen, sig: signal.Signals = signal.SIGTERM, timeout: float = 5.0) -> None:
    if proc.poll() is not None:
        return

    proc.send_signal(sig)
    try:
        proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()


def sudo_is_available() -> bool:
    proc = subprocess.run(
        ["sudo", "-n", "true"],
        cwd=ROOT_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def skip_uprobe(reason: str) -> tuple[None, str]:
    print("[uprobe] Skipping kernel uprobe benchmark...")
    print(f"  - {reason}")
    return None, reason


def read_process_until(proc: subprocess.Popen, marker: str, timeout: float = 30.0) -> str:
    fd = proc.stdout.fileno()
    buffer = bytearray()
    end_time = time.monotonic() + timeout
    marker_bytes = marker.encode("utf-8")

    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)

        while time.monotonic() < end_time:
            for key, _ in selector.select(timeout=0.2):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    text = buffer.decode("utf-8", errors="replace")
                    raise RuntimeError(f"process exited before marker {marker!r}:\n{text}")

                buffer.extend(chunk)
                if marker_bytes in buffer:
                    return buffer.decode("utf-8", errors="replace")

            if proc.poll() is not None:
                text = buffer.decode("utf-8", errors="replace")
                raise RuntimeError(f"process exited with code {proc.returncode} before marker {marker!r}:\n{text}")

    text = buffer.decode("utf-8", errors="replace")
    raise RuntimeError(f"timeout waiting for marker {marker!r}:\n{text}")


def wait_for_output(proc: subprocess.Popen, marker: str, timeout: float = 30.0) -> str:
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        raise RuntimeError(f"timeout waiting for marker {marker!r}:\n{out}")

    if proc.returncode != 0:
        raise RuntimeError(f"process failed while waiting for marker {marker!r}:\n{out}")

    if marker not in out:
        raise RuntimeError(f"marker {marker!r} not found in output:\n{out}")

    return out


def run_baseline(round_index: int) -> int:
    print(f"[baseline {round_index}/{BENCH_REPEATS}] Running baseline benchmark...")
    output = run_and_capture([str(TARGET), str(ITERATIONS)])
    append_round_output(BASELINE_OUT, round_index, output)
    total_ns = extract_total_ns(output)
    print(f"baseline total_ns={total_ns}")
    return total_ns


def run_uprobe(round_index: int) -> int:
    print(f"[uprobe {round_index}/{BENCH_REPEATS}] Running kernel uprobe benchmark...")
    target_proc = start_waiting_target()

    bpftrace_cmd = [
        "sudo",
        "-n",
        "bpftrace",
        "-e",
        f"uprobe:{TARGET}:bench_getpid {{ @n = count(); }}",
        "-p",
        str(target_proc.pid),
    ]
    bpftrace_proc = subprocess.Popen(
        bpftrace_cmd,
        cwd=ROOT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        time.sleep(1.0)
        os.kill(target_proc.pid, signal.SIGUSR1)
        target_output = wait_for_target_result(target_proc)
        bpftrace_proc.send_signal(signal.SIGINT)
        bpftrace_output, _ = bpftrace_proc.communicate(timeout=5.0)
    finally:
        stop_process(target_proc)
        stop_process(bpftrace_proc, sig=signal.SIGINT)

    if bpftrace_proc.returncode not in (0, 130):
        raise RuntimeError(
            f"bpftrace failed with code {bpftrace_proc.returncode} during uprobe benchmark:\n"
            f"{bpftrace_output}"
        )

    if "ERROR:" in bpftrace_output:
        raise RuntimeError(f"bpftrace reported an error during uprobe benchmark:\n{bpftrace_output}")

    hit_count = extract_bpftrace_count(bpftrace_output)
    if hit_count != ITERATIONS:
        raise RuntimeError(
            f"unexpected uprobe hit count: expected {ITERATIONS}, got {hit_count}\n"
            f"{bpftrace_output}"
        )

    append_round_output(UPROBE_TRACE_OUT, round_index, bpftrace_output)
    append_round_output(UPROBE_OUT, round_index, target_output)
    total_ns = extract_total_ns(target_output)
    print(f"uprobe total_ns={total_ns}")
    return total_ns


def run_ztrace(round_index: int) -> int:
    print(f"[ztrace {round_index}/{BENCH_REPEATS}] Running zeroTrace benchmark...")
    target_proc = start_waiting_target()

    runner_proc = subprocess.Popen(
        [str(BENCH_RUNNER), str(target_proc.pid), "bench_getpid", str(ZTRACE_LOG_OUT)],
        cwd=ROOT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        print("  - waiting for benchmark runner to become ready...")
        runner_output = read_process_until(runner_proc, "READY pid=", timeout=ZTRACE_RUNNER_TIMEOUT_SEC)
        os.kill(target_proc.pid, signal.SIGUSR1)
        target_output = wait_for_target_result(target_proc, timeout=ZTRACE_RUNNER_TIMEOUT_SEC)
        runner_output += wait_for_output(runner_proc, "DONE pid=", timeout=ZTRACE_RUNNER_TIMEOUT_SEC)
    finally:
        stop_process(target_proc)
        stop_process(runner_proc)

    append_round_output(ZTRACE_RUNNER_OUT, round_index, runner_output)
    append_round_output(ZTRACE_OUT, round_index, target_output)
    total_ns = extract_total_ns(target_output)
    print(f"ztrace total_ns={total_ns}")
    return total_ns


def run_latency() -> tuple[int, int]:
    print("[latency] Running install/uninstall latency benchmark...")
    target_proc = start_waiting_target()

    try:
        latency_proc = subprocess.run(
            [str(LATENCY_RUNNER), str(target_proc.pid), "bench_getpid", str(ZTRACE_LOG_OUT), str(LATENCY_ROUNDS)],
            cwd=ROOT_DIR,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    finally:
        stop_process(target_proc)

    write_text(LATENCY_OUT, latency_proc.stdout)
    install_ns, uninstall_ns = extract_latency_ns(latency_proc.stdout)
    print(f"install_ns={install_ns} uninstall_ns={uninstall_ns}")
    return install_ns, uninstall_ns


def format_report(baseline_runs: list[int],
                  uprobe_runs: list[int] | None,
                  ztrace_runs: list[int],
                  install_ns: int,
                  uninstall_ns: int,
                  uprobe_skip_reason: str | None = None) -> str:
    baseline_per_call = [value / ITERATIONS for value in baseline_runs]
    ztrace_per_call = [value / ITERATIONS for value in ztrace_runs]
    ztrace_overheads = [
        (ztrace_runs[i] - baseline_runs[i]) / ITERATIONS
        for i in range(min(len(ztrace_runs), len(baseline_runs)))
    ]

    if uprobe_runs:
        uprobe_per_call = [value / ITERATIONS for value in uprobe_runs]
        uprobe_overheads = [
            (uprobe_runs[i] - baseline_runs[i]) / ITERATIONS
            for i in range(min(len(uprobe_runs), len(baseline_runs)))
        ]
        ztrace_overhead_mean = mean_value(ztrace_overheads)
        uprobe_overhead_mean = mean_value(uprobe_overheads)
        ztrace_vs_uprobe = (
            uprobe_overhead_mean / ztrace_overhead_mean
            if ztrace_overhead_mean > 0 else 0.0
        )
        uprobe_section = (
            f"{format_int_stats('uprobe total ns      ', uprobe_runs, 'ns')}"
            f"{format_float_stats('uprobe per call      ', uprobe_per_call, 'ns')}"
            f"{format_float_stats('uprobe overhead/call ', uprobe_overheads, 'ns')}"
            f"ztrace vs uprobe      : {ztrace_vs_uprobe:.2f}x lower overhead\n"
        )
        uprobe_file_lines = (
            f"uprobe output   : {UPROBE_OUT}\n"
            f"uprobe trace    : {UPROBE_TRACE_OUT}\n"
        )
    else:
        if uprobe_skip_reason is None:
            uprobe_skip_reason = "kernel uprobe benchmark skipped"
        uprobe_section = (
            "uprobe total ns       : skipped\n"
            f"uprobe note           : {uprobe_skip_reason}\n"
            "uprobe per call       : skipped\n"
            "uprobe overhead/call  : skipped\n"
            "ztrace vs uprobe      : skipped\n"
        )
        uprobe_file_lines = (
            "uprobe output   : skipped\n"
            "uprobe trace    : skipped\n"
        )

    return (
        "Benchmark report\n"
        "================\n\n"
        f"iterations            : {ITERATIONS}\n"
        f"repeats               : {BENCH_REPEATS}\n"
        f"{format_int_stats('baseline total ns    ', baseline_runs, 'ns')}"
        f"{format_float_stats('baseline per call    ', baseline_per_call, 'ns')}"
        f"{uprobe_section}"
        f"{format_int_stats('ztrace total ns      ', ztrace_runs, 'ns')}"
        f"{format_float_stats('ztrace per call      ', ztrace_per_call, 'ns')}"
        f"{format_float_stats('ztrace overhead/call ', ztrace_overheads, 'ns')}"
        "\n"
        "Probe lifecycle latency\n"
        "-----------------------\n"
        f"install latency avg   : {install_ns} ns ({install_ns / NSEC_PER_MSEC:.3f} ms) over {LATENCY_ROUNDS} rounds\n"
        f"uninstall latency avg : {uninstall_ns} ns ({uninstall_ns / NSEC_PER_MSEC:.3f} ms) over {LATENCY_ROUNDS} rounds\n\n"
        "Files\n"
        "-----\n"
        f"baseline output : {BASELINE_OUT}\n"
        f"{uprobe_file_lines}"
        f"ztrace output   : {ZTRACE_OUT}\n"
        f"ztrace runner   : {ZTRACE_RUNNER_OUT}\n"
        f"ztrace trace log : {ZTRACE_LOG_OUT}\n"
        f"latency output  : {LATENCY_OUT}\n"
    )


def main() -> int:
    if ITERATIONS <= 0:
        print("ZT_BENCH_ITERATIONS must be positive", file=sys.stderr)
        return 1

    if BENCH_REPEATS <= 0:
        print("ZT_BENCH_REPEATS must be positive", file=sys.stderr)
        return 1

    if LATENCY_ROUNDS <= 0:
        print("ZT_BENCH_LATENCY_ROUNDS must be positive", file=sys.stderr)
        return 1

    if not TARGET.exists():
        print(f"benchmark target not built: {TARGET}", file=sys.stderr)
        print("run: make all", file=sys.stderr)
        return 1

    if not BENCH_RUNNER.exists():
        print(f"benchmark runner not built: {BENCH_RUNNER}", file=sys.stderr)
        print("run: make all", file=sys.stderr)
        return 1

    if not LATENCY_RUNNER.exists():
        print(f"latency runner not built: {LATENCY_RUNNER}", file=sys.stderr)
        print("run: make all", file=sys.stderr)
        return 1

    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    for path in RESULT_FILES:
        if path.exists():
            path.unlink()

    baseline_runs = [run_baseline(i) for i in range(1, BENCH_REPEATS + 1)]

    uprobe_skip_reason = None
    if shutil.which("bpftrace") is None:
        uprobe_runs, uprobe_skip_reason = skip_uprobe(
            "kernel uprobe benchmark skipped: bpftrace is not installed"
        )
    elif not sudo_is_available():
        uprobe_runs, uprobe_skip_reason = skip_uprobe(
            "kernel uprobe benchmark skipped: sudo is not available non-interactively"
        )
    else:
        uprobe_events_path = find_uprobe_events_path()
        if uprobe_events_path is None:
            uprobe_runs, uprobe_skip_reason = skip_uprobe(
                "kernel uprobe benchmark unsupported: "
                "no uprobe_events interface under /sys/kernel/tracing or /sys/kernel/debug/tracing"
            )
        else:
            print(f"  - detected uprobe_events at {uprobe_events_path}")
            uprobe_runs = [
                run_uprobe(i)
                for i in range(1, BENCH_REPEATS + 1)
            ]

    ztrace_runs = [run_ztrace(i) for i in range(1, BENCH_REPEATS + 1)]
    install_ns, uninstall_ns = run_latency()

    report = format_report(
        baseline_runs,
        uprobe_runs,
        ztrace_runs,
        install_ns,
        uninstall_ns,
        uprobe_skip_reason=uprobe_skip_reason,
    )
    write_text(REPORT_OUT, report)
    print()
    print(report, end="")
    print()
    print(f"report saved to: {REPORT_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
