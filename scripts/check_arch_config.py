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


def check_x86_64() -> None:
    config = read_arch_config("x86_64")

    require_contains(config, "ARCH_SRC_C", "src/isa/x86_64/arch.c")
    require_contains(config, "ARCH_SRC_C", "src/isa/x86_64/trampoline_manager.c")
    require_contains(config, "ARCH_SRC_S", "src/isa/x86_64/zt_stub.S")
    require_contains(config, "TEST_C", "src/test/test_trampoline_builder.c")
    require_absent(config, "ARCH_SRC_C", "src/isa/aarch64/arch.c")
    require_absent(config, "ARCH_SRC_C", "src/isa/aarch64/trampoline_manager.c")
    require_absent(config, "ARCH_SRC_S", "src/isa/aarch64/stub.S")
    require_absent(config, "TEST_C", "src/test/test_trampoline_builder_aarch64.c")


def check_aarch64() -> None:
    config = read_arch_config("aarch64")

    require_contains(config, "ARCH_SRC_C", "src/isa/aarch64/arch.c")
    require_contains(config, "ARCH_SRC_C", "src/isa/aarch64/trampoline_manager.c")
    require_contains(config, "ARCH_SRC_S", "src/isa/aarch64/stub.S")
    require_contains(config, "TEST_C", "src/test/test_trampoline_builder_aarch64.c")
    require_absent(config, "ARCH_SRC_C", "src/isa/x86_64/arch.c")
    require_absent(config, "ARCH_SRC_C", "src/isa/x86_64/trampoline_manager.c")
    require_absent(config, "ARCH_SRC_S", "src/isa/x86_64/zt_stub.S")
    require_absent(config, "TEST_C", "src/test/test_trampoline_builder.c")


def main() -> int:
    check_x86_64()
    check_aarch64()
    print("arch config self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
