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

"""Pre-flight check that a local .litertlm checkpoint is present.

Checkpoints are multi-gigabyte downloads, so an interrupted transfer is the
common failure mode. `tools/fetch_model.py` verifies the download against the
server's Content-Length; this module only confirms a file is there before the
runtime is started, and leaves format validation to litert-lm itself.
"""

import dataclasses
import os

MIN_PLAUSIBLE_BYTES = 1 << 20


@dataclasses.dataclass(frozen=True)
class CheckpointStatus:
  """Presence status for a local .litertlm checkpoint file."""

  path: str
  actual_size: int
  problem: str | None

  @property
  def ok(self) -> bool:
    return self.problem is None


def inspect(path: str) -> CheckpointStatus:
  """Confirms the checkpoint exists and is not an empty or partial stub."""
  if not os.path.exists(path):
    return CheckpointStatus(path, 0, "file does not exist")

  actual = os.path.getsize(path)
  if actual < MIN_PLAUSIBLE_BYTES:
    return CheckpointStatus(
        path, actual, f"file is only {actual:,} bytes — download is incomplete"
    )

  return CheckpointStatus(path, actual, None)


def require_valid(path: str) -> None:
  """Raises SystemExit if the checkpoint is missing or obviously incomplete."""
  status = inspect(path)
  if status.ok:
    return

  raise SystemExit(
      "\n".join([
          "",
          "Checkpoint failed pre-flight check.",
          f"  path    : {status.path}",
          f"  problem : {status.problem}",
          "",
          "Download or resume it with:",
          "  python3 tools/fetch_model.py --model 26b",
          "",
      ])
  )
