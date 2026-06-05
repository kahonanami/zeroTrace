#!/usr/bin/env python3
"""Validate Makefile architecture selection without cross-compiling.

The full aarch64 runtime test still belongs on an ARM64 machine. This check
keeps the host-independent part honest: selecting ARCH must switch the ISA
backend sources, stub assembly, and architecture-specific trampoline tests.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


ARCH_CHECKS = {
    "x86_64": {
        "present": {
            "ARCH_SRC_C": [
                "src/isa/x86_64/arch.c",
                "src/isa/x86_64/trampoline_manager.c",
            ],
            "ARCH_SRC_S": ["src/isa/x86_64/stub.S"],
            "TEST_C": ["src/test/test_trampoline_builder.c"],
        },
        "absent": {
            "ARCH_SRC_C": [
                "src/isa/aarch64/arch.c",
                "src/isa/aarch64/trampoline_manager.c",
            ],
            "ARCH_SRC_S": ["src/isa/aarch64/stub.S"],
            "TEST_C": ["src/test/test_trampoline_builder_aarch64.c"],
        },
    },
    "aarch64": {
        "present": {
            "ARCH_SRC_C": [
                "src/isa/aarch64/arch.c",
                "src/isa/aarch64/trampoline_manager.c",
            ],
            "ARCH_SRC_S": ["src/isa/aarch64/stub.S"],
            "TEST_C": ["src/test/test_trampoline_builder_aarch64.c"],
        },
        "absent": {
            "ARCH_SRC_C": [
                "src/isa/x86_64/arch.c",
                "src/isa/x86_64/trampoline_manager.c",
            ],
            "ARCH_SRC_S": ["src/isa/x86_64/stub.S"],
            "TEST_C": ["src/test/test_trampoline_builder.c"],
        },
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


def check_arch(arch: str) -> None:
    config = read_arch_config(arch)
    checks = ARCH_CHECKS[arch]

    for key, values in checks["present"].items():
        for value in values:
            require_contains(config, key, value)

    for key, values in checks["absent"].items():
        for value in values:
            require_absent(config, key, value)


def main() -> int:
    for arch in ARCH_CHECKS:
        check_arch(arch)
    print("arch config self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
