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

"""LiteRT-LM stateless-turn adapter for multi-agent workflows."""

import json as _stdlib_json
import re

try:
  from google.antigravity.connections.local import litert_server
except Exception:  # pylint: disable=broad-except
  litert_server = None

_REQUEST_TAG = re.compile(r"<USER_REQUEST>\n?(.*?)\n?</USER_REQUEST>", re.DOTALL)


class _ScopedJson:
  """Delegates stdlib json calls while scoping payload overrides to litert_server."""

  def __init__(self, loads):
    self.loads = loads

  def __getattr__(self, name):
    return getattr(_stdlib_json, name)


def configure_isolated_litert_context(
    system_prompt: str | None = None,
) -> bool:
  """Configures each LiteRT-LM turn to execute in an isolated context window."""
  if litert_server is None:
    return False
  if getattr(litert_server, "_isolated_patched", False):
    return True

  real_loads = _stdlib_json.loads

  def isolated_loads(payload, *args, **kwargs):
    data = real_loads(payload, *args, **kwargs)
    if isinstance(data, dict) and isinstance(data.get("messages"), list):
      messages = data["messages"]
      user_msgs = [
          m for m in messages
          if isinstance(m, dict) and m.get("role") == "user"
      ]
      if user_msgs:
        last_user = dict(user_msgs[-1])
        match = _REQUEST_TAG.search(last_user.get("content") or "")
        if match:
          last_user["content"] = match.group(1).strip()

        system = next(
            (dict(m) for m in messages
             if isinstance(m, dict) and m.get("role") == "system"),
            None,
        )
        if system_prompt is not None:
          system = {"role": "system", "content": system_prompt}

        data["messages"] = ([system] if system else []) + [last_user]
      data.pop("tools", None)
    return data

  try:
    litert_server.json = _ScopedJson(isolated_loads)
    original_thinking = litert_server.litert_lm.ThinkingConfig
    litert_server.litert_lm.ThinkingConfig = (
        lambda *a, **kw: original_thinking(enable_thinking=False)
    )
  except Exception:  # pylint: disable=broad-except
    return False

  litert_server._isolated_patched = True  # pylint: disable=protected-access
  return True
