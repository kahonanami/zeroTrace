# Test Layout

`src/test` is split by role so that probe runners and target fixtures do not
look like the same kind of test.

- `cases/`: automated test runners executed by `make test`.
- `targets/`: standalone target processes launched by test runners.
- `benchmark/`: benchmark target, runner, and lifecycle latency tools used by
  `make benchmark`.
- `manual/`: small demo programs intended for manual CLI experiments.
- `common/`: shared test helpers.

Fixtures under `targets/` normally wait for a runner signal or pipe protocol and
are skipped by `make run-tests`; running them directly is only useful when
debugging that specific fixture.

Coverage boundaries:

- `test_probe_lifecycle` owns basic install/trace/remove coverage, 16-probe
  coexistence, conditional install, call-action argument forwarding, and cleanup
  checks.
- `test_probe_hot_update` owns dynamic filter/call-action updates and
  enable/disable transitions. Do not duplicate those scenarios in lifecycle
  tests unless the update path itself changes.
- `test_thread_group_control` owns ptrace stop/resume coverage; `test_thread_safety`
  owns traced multi-thread runtime behavior.
