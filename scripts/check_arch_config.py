#!/usr/bin/env python3
"""Validate Makefile architecture selection without cross-compiling.

The full aarch64 runtime test still belongs on an aarch64 machine. This check
keeps the host-independent part honest: selecting ARCH must switch the ISA
backend sources, stub assembly, and architecture-specific trampoline tests.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


ARCH_EXPECTED = {
    "x86_64": {
        "ARCH_SRC_C": [
            "src/isa/x86_64/arch.c",
            "src/isa/x86_64/trampoline_manager.c",
        ],
        "ARCH_SRC_S": ["src/isa/x86_64/stub.S"],
        "TEST_C": ["src/test/cases/test_trampoline_builder.c"],
    },
    "aarch64": {
        "ARCH_SRC_C": [
            "src/isa/aarch64/arch.c",
            "src/isa/aarch64/trampoline_manager.c",
        ],
        "ARCH_SRC_S": ["src/isa/aarch64/stub.S"],
        "TEST_C": ["src/test/cases/test_trampoline_builder_aarch64.c"],
    },
}


def read_arch_config(arch: str) -> dict[str, list[str]]:
    result = subprocess.run(
        ["make", "-s", "print-arch-config", f"ARCH={arch}"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    config: dict[str, list[str]] = {}

    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep != "=":
            raise RuntimeError(f"malformed arch config line: {line!r}")
        config[key] = value.split()

    return config


def require_contains(config: dict[str, list[str]], key: str, value: str) -> None:
    values = config.get(key, [])
    if value not in values:
        raise RuntimeError(f"{key} for ARCH={config.get('ARCH', ['?'])[0]} misses {value}")


def require_absent(config: dict[str, list[str]], key: str, value: str) -> None:
    values = config.get(key, [])
    if value in values:
        raise RuntimeError(f"{key} for ARCH={config.get('ARCH', ['?'])[0]} unexpectedly contains {value}")


def require_text(path: str, needle: str, why: str) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    if needle not in text:
        raise RuntimeError(f"{path} misses {needle!r}: {why}")


def require_selected_arch(config: dict[str, list[str]], arch: str) -> None:
    selected = config.get("ARCH", [])
    if selected != [arch]:
        raise RuntimeError(f"requested ARCH={arch}, but Makefile reported ARCH={selected!r}")


def check_arch(arch: str) -> None:
    config = read_arch_config(arch)

    require_selected_arch(config, arch)

    for key, values in ARCH_EXPECTED[arch].items():
        for value in values:
            require_contains(config, key, value)

    for other_arch, expected in ARCH_EXPECTED.items():
        if other_arch == arch:
            continue

        for key, values in expected.items():
            for value in values:
                require_absent(config, key, value)


def main() -> int:
    for arch in ARCH_EXPECTED:
        check_arch(arch)

    require_text(
        "src/isa/aarch64/stub.S",
        ".equ ZT_FP_STATE_VEC_OFFSET, 0",
        "payload expects fp_state_area slot 0 to contain q0/d0",
    )

    print("arch config self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
