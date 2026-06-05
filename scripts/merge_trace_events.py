#!/usr/bin/env python3
"""Merge perf/ftrace-style event logs by timestamp.

zeroTrace emits lines like:

    comm-123/456 [007] 1234.567890123: ztrace:entry: foo(...)

This helper also accepts common ftrace/perf-script-like lines that include a
CPU field in brackets followed by an optional flags field and a timestamp:

    comm-123  [007] .... 1234.567890: sched_switch: ...

The script assumes the input logs already use the same clock domain, normally
CLOCK_MONOTONIC for zeroTrace and a matching trace clock for ftrace/perf.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


TRACE_LINE_RE = re.compile(
    r"^(?P<prefix>.*?\[(?P<cpu>\d+)\])"
    r"\s+"
    r"(?:(?P<flags>\S+)\s+)?"
    r"(?P<timestamp>\d+\.\d+):"
    r"(?P<body>.*)$"
)


@dataclass(order=True)
class TraceEvent:
    timestamp_ns: int
    source_index: int
    line_number: int
    source_name: str
    line: str


def timestamp_to_ns(value: str) -> int:
    seconds_text, fraction_text = value.split(".", 1)
    fraction_text = (fraction_text + "000000000")[:9]
    return int(seconds_text) * 1_000_000_000 + int(fraction_text)


def parse_trace_line(line: str) -> int | None:
    match = TRACE_LINE_RE.match(line)
    if match is None:
        return None

    return timestamp_to_ns(match.group("timestamp"))


def read_events(path: Path, source_index: int, keep_unparsed: bool) -> tuple[list[TraceEvent], int]:
    events: list[TraceEvent] = []
    skipped = 0

    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line_number, raw_line in enumerate(fp, start=1):
            line = raw_line.rstrip("\n")
            if line == "":
                continue

            timestamp_ns = parse_trace_line(line)
            if timestamp_ns is None:
                skipped += 1
                if keep_unparsed:
                    timestamp_ns = sys.maxsize
                else:
                    continue

            events.append(
                TraceEvent(
                    timestamp_ns=timestamp_ns,
                    source_index=source_index,
                    line_number=line_number,
                    source_name=path.name,
                    line=line,
                )
            )

    return events, skipped


def format_event(event: TraceEvent, show_source: bool) -> str:
    if not show_source:
        return event.line

    return f"{event.source_name}:{event.line_number}: {event.line}"


def run_self_test() -> int:
    samples = [
        "test_loop-100/100 [002] 10.000000300: ztrace:return: foo -> 0x1",
        "test_loop-100/100 [002] 10.000000100: ztrace:entry: foo(1)",
        "kworker-42  [001] d..2. 10.000000200: sched_switch: prev=a next=b",
    ]
    expected = [samples[1], samples[2], samples[0]]
    events: list[TraceEvent] = []

    for index, line in enumerate(samples):
        timestamp_ns = parse_trace_line(line)
        if timestamp_ns is None:
            raise RuntimeError(f"self-test failed to parse line: {line}")
        events.append(
            TraceEvent(
                timestamp_ns=timestamp_ns,
                source_index=0,
                line_number=index + 1,
                source_name="self-test",
                line=line,
            )
        )

    events.sort()
    actual = [event.line for event in events]
    if actual != expected:
        raise RuntimeError(f"self-test order mismatch:\nexpected={expected}\nactual={actual}")

    print("merge_trace_events self-test passed")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge zeroTrace/perf/ftrace-style event logs by timestamp.",
    )
    parser.add_argument(
        "logs",
        nargs="*",
        type=Path,
        help="Input log files that use a perf/ftrace-style timestamp field.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write merged output to this file instead of stdout.",
    )
    parser.add_argument(
        "--show-source",
        action="store_true",
        help="Prefix each merged line with input file name and line number.",
    )
    parser.add_argument(
        "--keep-unparsed",
        action="store_true",
        help="Keep unparsed lines at the end instead of skipping them.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run the built-in parser and ordering self-test.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if not args.logs:
        parser.error("at least one input log is required unless --self-test is used")

    events: list[TraceEvent] = []
    total_skipped = 0

    for source_index, path in enumerate(args.logs):
        if not path.exists():
            parser.error(f"input log does not exist: {path}")

        file_events, skipped = read_events(path, source_index, args.keep_unparsed)
        events.extend(file_events)
        total_skipped += skipped

    events.sort()
    output = "\n".join(format_event(event, args.show_source) for event in events)
    if output:
        output += "\n"

    if args.output is None:
        sys.stdout.write(output)
    else:
        args.output.write_text(output, encoding="utf-8")

    if total_skipped > 0 and not args.keep_unparsed:
        print(f"merge_trace_events.py: skipped {total_skipped} unparsed line(s)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
