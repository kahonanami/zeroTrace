#!/usr/bin/env python3
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


ITERATIONS = int(os.environ.get("ZT_BENCH_ITERATIONS", "1000000"))
LATENCY_ROUNDS = int(os.environ.get("ZT_BENCH_LATENCY_ROUNDS", "1000"))
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


def write_text(path: Path, data: str) -> None:
    path.write_text(data, encoding="utf-8")


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


def ensure_sudo() -> None:
    subprocess.run(
        ["sudo", "-v"],
        cwd=ROOT_DIR,
        check=True,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


def read_process_until(proc: subprocess.Popen, marker: str, timeout: float = 30.0) -> str:
    fd = proc.stdout.fileno()
    buffer = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(fd, selectors.EVENT_READ)
    end_time = time.monotonic() + timeout
    marker_bytes = marker.encode("utf-8")

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


def run_baseline() -> int:
    print("[1/3] Running baseline benchmark...")
    output = run_and_capture([str(TARGET), str(ITERATIONS)])
    write_text(BASELINE_OUT, output)
    total_ns = extract_total_ns(output)
    print(f"baseline total_ns={total_ns}")
    return total_ns


def run_uprobe() -> int:
    print("[2/3] Running kernel uprobe benchmark...")
    env = os.environ.copy()
    env["ZT_BENCH_WAIT_SIGUSR1"] = "1"
    target_proc = subprocess.Popen(
        [str(TARGET), str(ITERATIONS)],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

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

    time.sleep(1.0)
    os.kill(target_proc.pid, signal.SIGUSR1)
    target_output = wait_for_target_result(target_proc)
    bpftrace_proc.send_signal(signal.SIGINT)
    bpftrace_output, _ = bpftrace_proc.communicate(timeout=5.0)

    write_text(UPROBE_TRACE_OUT, bpftrace_output)
    write_text(UPROBE_OUT, target_output)
    total_ns = extract_total_ns(target_output)
    print(f"uprobe total_ns={total_ns}")
    return total_ns


def run_ztrace() -> int:
    print("[3/3] Running zeroTrace benchmark...")
    env = os.environ.copy()
    env["ZT_BENCH_WAIT_SIGUSR1"] = "1"
    target_proc = subprocess.Popen(
        [str(TARGET), str(ITERATIONS)],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    runner_proc = subprocess.Popen(
        [str(BENCH_RUNNER), str(target_proc.pid), "bench_getpid", str(ZTRACE_LOG_OUT)],
        cwd=ROOT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    print("  - waiting for benchmark runner to become ready...")
    runner_output = read_process_until(runner_proc, "READY pid=", timeout=20.0)
    os.kill(target_proc.pid, signal.SIGUSR1)
    target_output = wait_for_target_result(target_proc, timeout=20.0)
    runner_output += wait_for_output(runner_proc, "DONE pid=", timeout=20.0)

    write_text(ZTRACE_RUNNER_OUT, runner_output)
    write_text(ZTRACE_OUT, target_output)
    total_ns = extract_total_ns(target_output)
    print(f"ztrace total_ns={total_ns}")
    return total_ns


def run_latency() -> tuple[int, int]:
    print("[4/4] Running install/uninstall latency benchmark...")
    env = os.environ.copy()
    env["ZT_BENCH_WAIT_SIGUSR1"] = "1"
    target_proc = subprocess.Popen(
        [str(TARGET), str(ITERATIONS)],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    latency_proc = subprocess.run(
        [str(LATENCY_RUNNER), str(target_proc.pid), "bench_getpid", str(ZTRACE_LOG_OUT), str(LATENCY_ROUNDS)],
        cwd=ROOT_DIR,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    target_proc.send_signal(signal.SIGTERM)
    try:
        target_proc.communicate(timeout=5.0)
    except subprocess.TimeoutExpired:
        target_proc.kill()
        target_proc.communicate()

    write_text(LATENCY_OUT, latency_proc.stdout)
    install_ns, uninstall_ns = extract_latency_ns(latency_proc.stdout)
    print(f"install_ns={install_ns} uninstall_ns={uninstall_ns}")
    return install_ns, uninstall_ns


def format_report(baseline_ns: int,
                  uprobe_ns: int,
                  ztrace_ns: int,
                  install_ns: int,
                  uninstall_ns: int) -> str:
    baseline_per_call = baseline_ns / ITERATIONS
    uprobe_per_call = uprobe_ns / ITERATIONS
    ztrace_per_call = ztrace_ns / ITERATIONS

    uprobe_overhead = (uprobe_ns - baseline_ns) / ITERATIONS
    ztrace_overhead = (ztrace_ns - baseline_ns) / ITERATIONS

    ztrace_vs_uprobe = uprobe_overhead / ztrace_overhead if ztrace_overhead > 0 else 0.0

    return (
        "Benchmark report\n"
        "================\n\n"
        f"iterations            : {ITERATIONS}\n"
        f"baseline total ns     : {baseline_ns}\n"
        f"baseline per call     : {baseline_per_call:.2f} ns\n"
        f"uprobe total ns       : {uprobe_ns}\n"
        f"uprobe per call       : {uprobe_per_call:.2f} ns\n"
        f"uprobe overhead/call  : {uprobe_overhead:.2f} ns\n"
        f"ztrace total ns       : {ztrace_ns}\n"
        f"ztrace per call       : {ztrace_per_call:.2f} ns\n"
        f"ztrace overhead/call  : {ztrace_overhead:.2f} ns\n"
        f"ztrace vs uprobe      : {ztrace_vs_uprobe:.2f}x lower overhead\n\n"
        "Probe lifecycle latency\n"
        "-----------------------\n"
        f"install latency avg   : {install_ns} ns ({install_ns / 1000000.0:.3f} ms) over {LATENCY_ROUNDS} rounds\n"
        f"uninstall latency avg : {uninstall_ns} ns ({uninstall_ns / 1000000.0:.3f} ms) over {LATENCY_ROUNDS} rounds\n\n"
        "Files\n"
        "-----\n"
        f"baseline output : {BASELINE_OUT}\n"
        f"uprobe output   : {UPROBE_OUT}\n"
        f"uprobe trace    : {UPROBE_TRACE_OUT}\n"
        f"ztrace output   : {ZTRACE_OUT}\n"
        f"ztrace runner   : {ZTRACE_RUNNER_OUT}\n"
        f"ztrace trace log : {ZTRACE_LOG_OUT}\n"
        f"latency output  : {LATENCY_OUT}\n"
    )


def main() -> int:
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

    if shutil.which("bpftrace") is None:
        print("bpftrace is required for automated uprobe benchmark", file=sys.stderr)
        return 1

    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    for path in [BASELINE_OUT, UPROBE_OUT, UPROBE_TRACE_OUT, ZTRACE_OUT, ZTRACE_RUNNER_OUT, ZTRACE_LOG_OUT, LATENCY_OUT, REPORT_OUT]:
        if path.exists():
            path.unlink()

    ensure_sudo()

    baseline_ns = run_baseline()
    uprobe_ns = run_uprobe()
    ztrace_ns = run_ztrace()
    install_ns, uninstall_ns = run_latency()

    report = format_report(baseline_ns, uprobe_ns, ztrace_ns, install_ns, uninstall_ns)
    write_text(REPORT_OUT, report)
    print()
    print(report, end="")
    print()
    print(f"report saved to: {REPORT_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
