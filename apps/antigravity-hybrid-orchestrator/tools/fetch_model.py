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

"""Resumable, verifying downloader for Gemma 4 .litertlm checkpoints.

Usage:
    python tools/fetch_model.py 26B
    python tools/fetch_model.py E2B
"""

import os
import sys
import time
import urllib.error
import urllib.request

REPOS = {
    "E2B": (
        "litert-community/gemma-4-E2B-it-litert-lm",
        "gemma-4-E2B-it-gpu.litertlm",
        "gemma4-e2b",
    ),
    "E4B": (
        "litert-community/gemma-4-E4B-it-litert-lm",
        "gemma-4-E4B-it-gpu.litertlm",
        "gemma4-e4b",
    ),
    "12B": (
        "litert-community/gemma-4-12B-it-litert-lm",
        "gemma-4-12B-it-gpu.litertlm",
        "gemma4-12b",
    ),
    "26B": (
        "litert-community/gemma-4-26B-A4B-it-litert-lm",
        "gemma-4-26B-A4B-it-gpu.litertlm",
        "gemma4-26b",
    ),
}

MAX_ATTEMPTS = 200
CHUNK = 1 << 20


def expected_size(url: str) -> int:
  """Returns the server's advertised length, following redirects."""
  req = urllib.request.Request(url, method="HEAD")
  with urllib.request.urlopen(req, timeout=60) as r:
    size = r.headers.get("Content-Length")
    if size is None:
      raise RuntimeError("server did not advertise Content-Length")
    return int(size)


def fetch(url: str, dest: str, total: int) -> None:
  """Downloads `url` to `dest`, resuming until the file is exactly `total`."""
  os.makedirs(os.path.dirname(dest), exist_ok=True)

  for attempt in range(1, MAX_ATTEMPTS + 1):
    have = os.path.getsize(dest) if os.path.exists(dest) else 0
    if have == total:
      return
    if have > total:
      raise RuntimeError(f"{dest} is larger than expected; delete and retry")

    req = urllib.request.Request(url, headers={"Range": f"bytes={have}-"})
    started, t0 = have, time.monotonic()
    try:
      with urllib.request.urlopen(req, timeout=120) as r:
        if have and r.status != 206:
          raise RuntimeError(f"server refused range request (status {r.status})")
        with open(dest, "ab") as f:
          while True:
            block = r.read(CHUNK)
            if not block:
              break
            f.write(block)
            have += len(block)
            pct = 100.0 * have / total
            rate = (have - started) / 1e6 / max(time.monotonic() - t0, 1e-6)
            print(
                f"\r  {have/1e9:6.2f}/{total/1e9:.2f} GB  {pct:5.1f}%  "
                f"{rate:5.2f} MB/s  (attempt {attempt})",
                end="",
                flush=True,
            )
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
      print(f"\n  interrupted at {have/1e9:.2f} GB: {type(e).__name__}: {e}")
      time.sleep(min(2 * attempt, 30))
      continue

    have = os.path.getsize(dest)
    if have == total:
      print()
      return
    print(f"\n  short read: {have/1e9:.2f} of {total/1e9:.2f} GB, resuming")
    time.sleep(2)

  raise RuntimeError(f"gave up after {MAX_ATTEMPTS} attempts")


def main() -> int:
  import argparse  # pylint: disable=import-outside-toplevel

  parser = argparse.ArgumentParser(
      description="Download and verify Gemma 4 .litertlm checkpoints from HuggingFace."
  )
  parser.add_argument(
      "pos_model",
      nargs="?",
      help="Model size to download: 26B, 12B, E4B, or E2B (case-insensitive).",
  )
  parser.add_argument(
      "--model",
      "-m",
      dest="flag_model",
      help="Model size to download: 26b, 12b, e4b, or e2b (case-insensitive).",
  )
  parser.add_argument(
      "--check",
      action="store_true",
      help="Verify remote HuggingFace URL Content-Length and local checkpoint status without downloading.",
  )
  args = parser.parse_args()
  raw_choice = (args.flag_model or args.pos_model or "26B").upper()
  if raw_choice not in REPOS:
    print(f"usage: {sys.argv[0]} [--model] [{'|'.join(REPOS)}]")
    return 2

  repo, filename, model_id = REPOS[raw_choice]
  url = f"https://huggingface.co/{repo}/resolve/main/{filename}"
  dest = os.path.expanduser(f"~/.litert-lm/models/{model_id}/model.litertlm")

  print(f"source: {url}")
  print(f"target: {dest}")
  total = expected_size(url)
  print(f"size:   {total:,} bytes ({total/1e9:.2f} GB)")

  if args.check:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import checkpoint  # pylint: disable=import-outside-toplevel

    status = checkpoint.inspect(dest)
    summary = (
        f"OK ({status.actual_size:,} bytes verified)"
        if status.ok
        else f"MISSING/INVALID ({status.problem})"
    )
    print(f"local:  {summary}")
    return 0

  fetch(url, dest, total)

  sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
  import checkpoint  # pylint: disable=import-outside-toplevel

  checkpoint.require_valid(dest)
  print(f"ok:     {dest} verified ({total:,} bytes)")
  return 0


if __name__ == "__main__":
  sys.exit(main())
