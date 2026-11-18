# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Verification test suite for the built-in sandbox modules.

Usage:
    python verification_tests.py auth
    python verification_tests.py billing
    python verification_tests.py database

Prints a single JSON line: {"passed": int, "failed": int, "failures": [str]}
"""

import importlib
import json
import os
import sqlite3
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
  sys.path.insert(0, HERE)


def _fresh(name):
  """Imports a module from disk, reloading any cached entry."""
  if name in sys.modules:
    del sys.modules[name]
  return importlib.import_module(name)


def auth_rejects_missing_secret():
  """get_key() must raise when JWT_SECRET_KEY is unset rather than using a hardcoded fallback."""
  auth = _fresh("auth")
  os.environ.pop("JWT_SECRET_KEY", None)
  try:
    key = auth.get_key()
  except Exception:
    return
  raise AssertionError(f"returned fallback secret {key!r} instead of raising")


def auth_uses_env_secret():
  auth = _fresh("auth")
  os.environ["JWT_SECRET_KEY"] = "unit-test-secret"
  try:
    key = auth.get_key()
    assert key == "unit-test-secret", (
        f"expected JWT_SECRET_KEY from environment, got {key!r}"
    )
  finally:
    os.environ.pop("JWT_SECRET_KEY", None)


def billing_single_debit():
  billing = _fresh("billing")
  billing.balances["usr_alice"] = 100.0
  ok = billing.debit("usr_alice", 30.0)
  assert ok is True, f"valid 30.0 debit was refused (returned {ok!r})"
  balance = billing.balances["usr_alice"]
  assert abs(balance - 70.0) < 1e-9, (
      f"balance after 30.0 debit from 100.0 should be 70.00, got {balance:.2f}"
  )


def billing_survives_concurrent_debits():
  """Ten concurrent threads attempt to spend a balance that covers five debits."""
  billing = _fresh("billing")
  billing.balances["usr_alice"] = 100.0

  wins = []
  lock = threading.Lock()

  def worker():
    if billing.debit("usr_alice", 20.0):
      with lock:
        wins.append(1)

  threads = [threading.Thread(target=worker) for _ in range(10)]
  for t in threads:
    t.start()
  for t in threads:
    t.join()

  final = billing.balances["usr_alice"]
  if len(wins) != 5 or abs(final) > 1e-9:
    raise AssertionError(
        f"balance drift: {len(wins)} debits succeeded, final balance {final:.2f}"
        " (expected 5 and 0.00)"
    )


def _seed_db():
  conn = sqlite3.connect(":memory:")
  conn.execute("CREATE TABLE users (username TEXT, role TEXT)")
  conn.execute("INSERT INTO users VALUES ('alice', 'user')")
  conn.execute("INSERT INTO users VALUES ('root', 'admin')")
  conn.commit()
  return conn


def database_finds_user():
  database = _fresh("database")
  conn = _seed_db()
  rows = database.find_user(conn, "alice")
  assert len(rows) == 1, (
      f"lookup returned {len(rows)} rows, expected 1"
  )


def database_blocks_injection():
  """SQL injection payload must return zero rows or raise an error."""
  database = _fresh("database")
  conn = _seed_db()
  try:
    rows = database.find_user(conn, "' OR '1'='1")
  except Exception:
    return
  if len(rows) != 0:
    raise AssertionError(
        f"injection probe returned {len(rows)} rows — auth bypassed"
    )


SUITES = {
    "auth": [auth_uses_env_secret, auth_rejects_missing_secret],
    "billing": [billing_single_debit, billing_survives_concurrent_debits],
    "database": [database_finds_user, database_blocks_injection],
}


def main():
  which = sys.argv[1] if len(sys.argv) > 1 else "auth"
  passed, failures = 0, []

  if which not in SUITES:
    print(json.dumps({
        "passed": 0,
        "failed": 1,
        "failures": [f"unknown suite {which!r}; expected one of {sorted(SUITES)}"],
    }))
    return 1

  for check in SUITES[which]:
    try:
      check()
      passed += 1
    except Exception as exc:  # noqa: BLE001
      failures.append(f"{check.__name__}: {exc}")

  print(json.dumps({"passed": passed, "failed": len(failures), "failures": failures}))
  return min(len(failures), 125)


if __name__ == "__main__":
  sys.exit(main())
