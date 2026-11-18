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

"""Antigravity Hybrid Orchestrator — Cloud Architect + On-Device Gemma 4 Swarm.

Usage:
    ./run.sh                  run the interactive Rich terminal HUD
    ./run.sh --minimal        run the headless CLI quickstart
    ./run.sh --snapshot       render a static preview of the HUD
    ./run.sh --files <path> --test-cmd "<cmd>"
"""

import ast
import asyncio
import importlib
import inspect
import json
import logging
import os
import random
import re
import sys
import textwrap
import time

import checkpoint
from google.antigravity import Agent
from google.antigravity import CapabilitiesConfig
from google.antigravity import LiteRTAgentConfig
from google.antigravity import LocalAgentConfig
import hud
from rich.markup import escape as rich_escape
from runtime_compat import configure_isolated_litert_context

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.join(HERE, "sandbox")
OUT_DIR = os.path.join(HERE, "out")

DEMO_SECONDS = float(os.environ.get("DEMO_SECONDS", "900"))
MAX_LANE_LOOPS = int(os.environ.get("MAX_LANE_LOOPS", "5"))


def cloud_model_label() -> str:
  """Returns the display label for the configured cloud model."""
  try:
    from google.antigravity import models  # pylint: disable=import-outside-toplevel

    raw = str(models.DEFAULT_MODEL)
  except Exception:  # pylint: disable=broad-except
    raw = "gemini-3.8-flash"

  parts = raw.split("-")
  return " ".join(p.capitalize() if p.isalpha() else p for p in parts)


MODEL_SIZES = ("26b", "12b", "e4b", "e2b")


def local_model_labels(model_path: str) -> tuple[str, str]:
  """Returns (short, long) display names for the on-device checkpoint."""
  lowered = model_path.lower()
  size = next((s.upper() for s in MODEL_SIZES if s in lowered), "")
  short = f"Gemma 4 {size}" if size else "Gemma 4"
  long = f"{short} · on-device"
  return short, long


CLOUD = hud.CLOUD
LOCAL_C = hud.LOCAL


VULNERABLE = {
    "auth.py": textwrap.dedent('''\
        """Authentication and token validation."""
        import os

        FALLBACK_SECRET = "sk-live-prod-9948"

        def get_key():
            return os.environ.get("JWT_SECRET_KEY", FALLBACK_SECRET)
    '''),
    "billing.py": textwrap.dedent('''\
        """Wallet balance service."""
        import time

        balances = {"usr_alice": 100.0}

        def debit(user_id: str, amount: float) -> bool:
            current = balances.get(user_id, 0.0)
            if current >= amount:
                time.sleep(0.002)
                balances[user_id] = current - amount
                return True
            return False
    '''),
    "database.py": textwrap.dedent('''\
        """User lookup."""
        import sqlite3

        def find_user(conn: sqlite3.Connection, username: str):
            cursor = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}'"
            cursor.execute(query)
            return cursor.fetchall()
    '''),
}

BUILDERS = {
    "minimal": (
        "Make the smallest change that fixes the flaw. "
        "Touch as few lines as possible. Do not add new dependencies."
    ),
    "defensive": (
        "Fix the flaw and harden the function. "
        "Validate inputs and fail loudly rather than silently."
    ),
}

FENCE = re.compile(r"```(?:python)?\n(.*?)```", re.DOTALL)
_VERDICT = re.compile(r"(?:^|[^0-9])([12])(?:[^0-9]|$)")
_NAMED_CANDIDATE = re.compile(r"\bcandidate\s*#?([12])\b", re.IGNORECASE)


def parse_verdict(reply: str) -> int | None:
  """Extracts candidate choice (1 or 2) from a blind critic response."""
  text = reply.strip()
  lead_named = re.match(
      r"^\s*[12]\s*[-–—:]\s*candidate\s*([12])\b", text, re.IGNORECASE
  )
  if lead_named:
    return int(lead_named.group(1))
  match = _VERDICT.search(text)
  return int(match.group(1)) if match else None


def extract_code(reply: str) -> str:
  """Extracts Python source code from a model response."""
  match = FENCE.search(reply)
  candidate = match.group(1) if match else reply
  return candidate.strip() + "\n"


def is_valid_python(source: str) -> bool:
  """Returns True if `source` parses as valid Python and defines a function or class."""
  if not source.strip():
    return False
  try:
    tree = compile(source, "<candidate>", "exec", ast.PyCF_ONLY_AST)
  except SyntaxError:
    return False
  defines = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
  return any(isinstance(node, defines) for node in ast.walk(tree))


def strip_suite_checks(source: str, check_names: set[str]) -> str:
  """Removes top-level functions whose names match test suite check functions."""
  if not check_names:
    return source
  try:
    tree = compile(source, "<candidate>", "exec", ast.PyCF_ONLY_AST)
  except SyntaxError:
    return source

  doomed = [
      node for node in tree.body
      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
      and node.name in check_names
  ]
  if not doomed:
    return source

  lines = source.splitlines(keepends=True)
  drop: set[int] = set()
  for node in doomed:
    start = min([node.lineno] + [d.lineno for d in node.decorator_list])
    end = node.end_lineno or node.lineno
    drop.update(range(start - 1, end))

  kept = [line for i, line in enumerate(lines) if i not in drop]
  cleaned = "".join(kept).rstrip() + "\n"
  return cleaned if is_valid_python(cleaned) else source


FILE_PATHS: dict[str, str] = {}
CUSTOM_TEST_CMD: str | None = None


def resolve_lane_path(name: str) -> str:
  """Returns the filesystem path for a target module."""
  return FILE_PATHS.get(name, os.path.join(WORKSPACE, name))


def extract_public_skeleton(filepath: str) -> str:
  """Extracts module imports, global names, and function/class signatures via AST."""
  try:
    with open(filepath, encoding="utf-8") as handle:
      tree = ast.parse(handle.read(), filename=os.path.basename(filepath))
  except Exception:  # pylint: disable=broad-except
    return "imports=[] globals=[] defs=[]"

  imports: list[str] = []
  globals_list: list[str] = []
  defs: list[str] = []

  for node in tree.body:
    if isinstance(node, ast.Import):
      imports.extend(alias.name for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
      imports.append(node.module)
    elif isinstance(node, ast.Assign):
      for target in node.targets:
        if isinstance(target, ast.Name):
          globals_list.append(target.id)
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
      globals_list.append(node.target.id)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
      args = [a.arg for a in node.args.args]
      prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
      defs.append(f"{prefix}{node.name}({', '.join(args)})")
    elif isinstance(node, ast.ClassDef):
      methods = [
          n.name for n in node.body
          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
      ]
      defs.append(f"class {node.name}[{', '.join(methods)}]")

  return (
      f"imports=[{', '.join(imports)}] "
      f"globals=[{', '.join(globals_list)}] "
      f"defs=[{', '.join(defs)}]"
  )


def reset_workspace() -> None:
  os.makedirs(WORKSPACE, exist_ok=True)
  for name, body in VULNERABLE.items():
    with open(os.path.join(WORKSPACE, name), "w") as handle:
      handle.write(body)


def resolve_model_path() -> str:
  override = os.environ.get("LITERT_MODEL_PATH")
  if override and os.path.exists(os.path.expanduser(override)):
    return os.path.expanduser(override)

  root = os.path.expanduser(
      os.environ.get("LITERT_MODEL_DIR", "~/.litert-lm/models")
  )
  preferred = os.environ.get("MODEL", "26b").lower()
  ordered = [preferred] + [s for s in MODEL_SIZES if s != preferred]
  for size in ordered:
    candidate = os.path.join(root, f"gemma4-{size}", "model.litertlm")
    if os.path.exists(candidate):
      return candidate
  sys.exit(
      "\nNo Gemma 4 .litertlm checkpoint found.\n\n"
      f"Looked in: {root}/gemma4-{{{','.join(ordered)}}}/model.litertlm\n\n"
      "Download one first:\n"
      "  python3 tools/fetch_model.py --model e2b    # ~2.0 GB\n"
      "  python3 tools/fetch_model.py --model e4b    # ~3.0 GB\n"
      "  python3 tools/fetch_model.py --model 12b    # ~6.0 GB\n"
      "  python3 tools/fetch_model.py --model 26b    # ~15.8 GB\n\n"
      "Or point to an existing checkpoint:\n"
      "  LITERT_MODEL_PATH=/path/to/model.litertlm ./run.sh\n\n"
      "To preview the static HUD without a checkpoint:\n"
      "  ./run.sh --snapshot\n"
  )


async def _run_custom_test_cmd(cmd: str) -> tuple[int, int, str]:
  """Executes a custom test command and returns (passed, failed, detail)."""
  proc = await asyncio.create_subprocess_shell(
      cmd,
      stdout=asyncio.subprocess.PIPE,
      stderr=asyncio.subprocess.PIPE,
      cwd=os.getcwd(),
  )
  out, err = await proc.communicate()
  combined = (out.decode(errors="replace") + "\n" + err.decode(errors="replace")).strip()
  if os.environ.get("DEMO_VERBOSE") == "1" and combined:
    print(f"[test-cmd] output:\n{combined}", file=sys.stderr)

  m_pass = re.search(r"(\d+)\s+passed", combined)
  m_fail = re.search(r"(\d+)\s+(?:failed|error|errors)", combined)
  passed = int(m_pass.group(1)) if m_pass else (1 if proc.returncode == 0 else 0)
  failed = int(m_fail.group(1)) if m_fail else (0 if proc.returncode == 0 else 1)

  if proc.returncode == 0 and failed == 0:
    return max(1, passed), 0, ""

  failed = max(1, failed)
  detail = "test command exited non-zero"
  for line in reversed(combined.splitlines()):
    s = line.strip()
    if s and not s.startswith("=") and not s.startswith("-"):
      detail = s
      if any(k in s for k in ("AssertionError", "Error:", "FAILED", "E   ")):
        break
  return passed, failed, detail


async def run_tests(module: str) -> tuple[int, int, str]:
  """Runs the verification test suite in a subprocess."""
  if CUSTOM_TEST_CMD:
    return await _run_custom_test_cmd(CUSTOM_TEST_CMD)

  proc = await asyncio.create_subprocess_exec(
      sys.executable,
      os.path.join(WORKSPACE, "verification_tests.py"),
      module,
      stdout=asyncio.subprocess.PIPE,
      stderr=asyncio.subprocess.PIPE,
      cwd=WORKSPACE,
  )
  out, err = await proc.communicate()
  if err and os.environ.get("DEMO_VERBOSE") == "1":
    print(f"[{module}] stderr:\n" + err.decode(errors="replace"), file=sys.stderr)
  try:
    data = json.loads(out.decode().strip().splitlines()[-1])
  except (ValueError, IndexError):
    return 0, 1, "test runner produced no parseable result"

  failures = data.get("failures") or []
  passed = data.get("passed", 0)
  failed = data.get("failed", 0)
  if passed == 0 and failed == 0:
    return 0, 1, f"no checks ran for {module!r}"

  detail = ""
  if failures:
    name, _, message = failures[0].partition(": ")
    detail = message.strip() or f"{name} failed"
  return passed, failed, detail


FALLBACK_PLAN = [
    {
        "file": "auth.py",
        "role": "CWE-798 Secret",
        "strategy": "Remove FALLBACK_SECRET; read JWT_SECRET_KEY from os.environ and raise RuntimeError/ValueError if unset or empty.",
        "invariant": "Preserve module-level get_key() -> str signature.",
    },
    {
        "file": "billing.py",
        "role": "CWE-362 Lock",
        "strategy": "Guard the balance check and decrement in debit() with a module-level threading.Lock() to prevent race conditions.",
        "invariant": "Preserve module-level balances dict and debit(user_id, amount) -> bool.",
    },
    {
        "file": "database.py",
        "role": "CWE-89 SQLi",
        "strategy": "Replace string interpolation with parameterized cursor.execute('SELECT ... WHERE username = ?', (username,)).",
        "invariant": "Preserve find_user(conn, username) returning cursor.fetchall().",
    },
]


def _fallback_for_files(files: list[str]) -> list[dict]:
  by_name = {item["file"]: item for item in FALLBACK_PLAN}
  out = []
  for f in files:
    if f in by_name:
      out.append(dict(by_name[f]))
    else:
      skel = extract_public_skeleton(resolve_lane_path(f))
      out.append({
          "file": f,
          "role": "Code Audit",
          "strategy": "Fix the defect exposed by the failing test with minimal surface change and explicit input validation.",
          "invariant": f"Preserve public definitions ({skel}).",
      })
  return out


async def plan_with_gemini(
    task: str, files: list[str], manager: Agent | None = None
) -> tuple[list[dict], int, str]:
  """Sends AST skeletons to Gemini 3.8 Flash and returns the architectural blueprint."""
  skeletons = {f: extract_public_skeleton(resolve_lane_path(f)) for f in files}
  skeleton_lines = "\n".join(f"  - {f}: {skeletons[f]}" for f in files)
  prompt = (
      f"Task: {task}\n"
      "Structural AST Skeletons (imports, global names, and function signatures ONLY — "
      f"0 bytes of function bodies or secret literals):\n{skeleton_lines}\n\n"
      "Act as the Chief Security Architect. For each file, diagnose the likely "
      "vulnerability class (e.g. CWE) from its structural surface, prescribe a "
      "1-sentence remediation strategy for the on-device builders, and state the "
      "module-level API invariant that callers depend on.\n"
      'Reply with JSON only: [{"file": "...", "role": "<short CWE/focus, <=14 chars>", '
      '"strategy": "<1-sentence fix blueprint>", "invariant": "<names/signatures to preserve>"}]'
  )

  fallback = _fallback_for_files(files)
  has_key = os.environ.get("GEMINI_API_KEY") or (
      os.environ.get("GOOGLE_GENAI_USE_VERTEXAI") == "true"
  )
  if not has_key:
    return fallback, 0, "no cloud credential — using local plan"

  async def _run_plan(mgr: Agent) -> tuple[int, str, list[dict]]:
    response = await mgr.chat(prompt)
    raw = await response.text()

    usage = response.usage_metadata
    if usage:
      out_tok = usage.candidates_token_count or 0
      tokens = estimate_tokens(prompt) + (out_tok or estimate_tokens(raw))
    else:
      tokens = estimate_tokens(prompt) + estimate_tokens(raw)

    defaults = {item["file"]: item for item in fallback}
    match = re.search(r"\[.*\]", raw, re.DOTALL)
    plan = []
    if match:
      for item in json.loads(match.group(0)):
        fname = item.get("file")
        if fname in files:
          d = defaults[fname]
          plan.append({
              "file": fname,
              "role": str(item.get("role") or d["role"]).strip()[:14],
              "strategy": str(item.get("strategy") or d["strategy"]).strip(),
              "invariant": str(item.get("invariant") or d["invariant"]).strip(),
          })
    return (plan or fallback), tokens, ""

  try:
    if manager is not None:
      return await _run_plan(manager)

    config = LocalAgentConfig(
        system_instructions="You are a terse chief security architect. Reply with JSON only.",
        capabilities=CapabilitiesConfig(enabled_tools=[]),
    )
    async with Agent(config) as mgr:
      return await _run_plan(mgr)
  except Exception as exc:  # pylint: disable=broad-except
    return fallback, 0, f"cloud call failed ({type(exc).__name__})"


def estimate_tokens(text: str) -> int:
  """Approximates token count (~4 chars/token) for local LiteRT-LM turns."""
  return max(1, len(text) // 4)


def load_suite_excerpts() -> dict[str, str]:
  """Extracts per-module check source code from the verification suite."""
  if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)
  suite = importlib.import_module("verification_tests")

  excerpts: dict[str, str] = {}
  for module, checks in suite.SUITES.items():
    blocks = []
    for check in checks:
      try:
        blocks.append(inspect.getsource(check))
      except OSError:
        continue
    excerpts[module] = "\n".join(blocks)
  return excerpts


def load_suite_check_names() -> dict[str, set[str]]:
  """Maps each module to the function names of its verification checks."""
  if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)
  suite = importlib.import_module("verification_tests")
  return {
      module: {check.__name__ for check in checks}
      for module, checks in suite.SUITES.items()
  }


class Swarm:
  """Coordinates on-device Gemma 4 builder and critic turns across file lanes."""

  def __init__(self, state: hud.SwarmState, agent: Agent, deadline: float):
    self.state = state
    self.agent = agent
    self.deadline = deadline
    self.turn_lock = asyncio.Lock()
    self.last_detail = ""
    self.suite_excerpts = load_suite_excerpts()
    self.suite_check_names = load_suite_check_names()

  def excerpt_for(self, lane_name: str) -> str:
    return self.suite_excerpts.get(lane_name.removesuffix(".py"), "")

  def check_names_for(self, lane_name: str) -> set[str]:
    return self.suite_check_names.get(lane_name.removesuffix(".py"), set())

  def expired(self) -> bool:
    return time.monotonic() >= self.deadline

  def _focus(self, lane: hud.Lane, role: str) -> None:
    self.state.focus_name = lane.name
    self.state.focus_role = role

  async def _turn(
      self,
      lane: hud.Lane,
      prompt: str,
      fresh: bool = True,
  ) -> str:
    """Executes one local Gemma 4 turn and streams tokens into the HUD."""
    started = time.perf_counter()
    if fresh:
      self.agent.conversation.clear_history()

    async def prefill_spinner() -> None:
      frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
      index = 0
      while True:
        waited = time.perf_counter() - started
        self.state.focus_partial = (
            f"{frames[index % len(frames)]} {lane.name} · {self.state.local_model}"
            f" reading file and tests (prefill)… {waited:.1f}s"
        )
        index += 1
        await asyncio.sleep(0.08)

    spinner = asyncio.create_task(prefill_spinner())
    response = await self.agent.chat(prompt)

    chunks: list[str] = []
    try:
      async for delta in response:
        if not spinner.done():
          spinner.cancel()
        chunks.append(delta)
        self.state.focus_partial = "".join(chunks).replace("\n", " ")[-92:]
    finally:
      spinner.cancel()

    reply = "".join(chunks)
    elapsed = max(1e-6, time.perf_counter() - started)

    out_tokens = estimate_tokens(reply)
    lane.tokens += estimate_tokens(prompt) + out_tokens
    lane.tok_s = out_tokens / elapsed
    self.state.local_tokens += estimate_tokens(prompt) + out_tokens
    self.state.focus_partial = ""
    return reply

  async def test(self, lane: hud.Lane, role: str, label: str) -> bool:
    """Runs the verification suite for a lane and returns True if all checks pass."""
    async with self.turn_lock:
      lane.status = label
      lane.active = True
      self._focus(lane, role)

      module = lane.name.removesuffix(".py")
      passed, failed, detail = await run_tests(module)
      lane.passed, lane.failed = passed, failed
      self.last_detail = detail
      green = failed == 0 and passed > 0

      if green:
        self.state.push(
            f"  [#5ddba4]✔[/] [bold white]{lane.name:<11}[/] [#5ddba4]adversarial suite green ({passed}/{passed + failed} passed)[/]"
        )
      else:
        self.state.push(
            f"  [#ff6b81]✗[/] [bold white]{lane.name:<11}[/] [#ff6b81]suite red ({passed}/{passed + failed} passed): {rich_escape(detail[:44])}[/]"
        )

      lane.active = False
      return green

  async def build(
      self,
      lane: hud.Lane,
      mandate: str,
      code: str,
      failure: str = "",
  ) -> str:
    """Runs one builder turn and returns candidate Python source."""
    architect_ctx = ""
    if lane.strategy or lane.invariant:
      architect_ctx = (
          f"Cloud Architect Blueprint ({self.state.cloud_model}):\n"
          + (f"  - Fix Strategy: {lane.strategy}\n" if lane.strategy else "")
          + (f"  - API Invariant: {lane.invariant}\n" if lane.invariant else "")
          + "\n"
      )
    excerpt = self.excerpt_for(lane.name)
    checks_ctx = (
        "For reference only, these checks will be run against your file from "
        "a separate test module. Do NOT include them in your reply:\n"
        f"{excerpt}\n\n"
        if excerpt
        else ""
    )
    prompt = (
        f"{BUILDERS[mandate]}\n\n"
        + architect_ctx
        + f"File {lane.name}:\n{code}\n\n"
        + checks_ctx
        + (f"Current failure: {failure}\n\n" if failure else "")
        + "Keep the module's public interface exactly as it is — the checks "
        "call these names at module level, so do not rename them, move them "
        "onto a class, or change their signatures.\n"
        "Reply with only the contents of "
        f"{lane.name} as one Python code block. No tests, no explanation."
    )

    async with self.turn_lock:
      lane.active = True
      lane.status = f"builder · {mandate}"
      self._focus(lane, f"builder · {mandate}")

      reply = await self._turn(lane, prompt)
      candidate = strip_suite_checks(
          extract_code(reply), self.check_names_for(lane.name)
      )

      ok = is_valid_python(candidate)
      lines = len(candidate.strip().splitlines())
      label = "Builder A (minimal)" if mandate == "minimal" else "Builder B (defensive)"
      if ok:
        self.state.push(
            f"  [#4dd0e1]▸[/] [bold white]{lane.name:<11}[/] [#4dd0e1]{label} authored {lines}-line patch ({lane.tok_s:.0f} tok/s)[/]"
        )
      else:
        self.state.push(
            f"  [#ff6b81]▸[/] [bold white]{lane.name:<11}[/] [#ff6b81]{label} patch failed AST check[/]"
        )

      lane.active = False
      return candidate if ok else ""

  async def critique(
      self,
      lane: hud.Lane,
      first: str,
      second: str,
  ) -> tuple[int, str]:
    """Runs a blind comparison between two candidate rewrites."""
    criteria = (
        f"Cloud Architect Blueprint: {lane.strategy} "
        f"(Invariant: {lane.invariant})\n\n"
        if (lane.strategy or lane.invariant)
        else ""
    )
    prompt = (
        f"Two candidate rewrites of {lane.name}. Judge them on correctness "
        "first, then on how little risk they add.\n\n"
        + criteria
        + f"Candidate 1:\n{first}\n\n"
        f"Candidate 2:\n{second}\n\n"
        "Reply exactly: '1' or '2', then a dash, then under 12 words of "
        "justification. Pick one. Do not score them."
    )

    async with self.turn_lock:
      lane.active = True
      lane.status = "blind critic"
      self._focus(lane, "blind critic")

      reply = await self._turn(lane, prompt, fresh=True)

      verdict = reply.strip()
      parsed = parse_verdict(verdict)
      choice = parsed or 1
      reason = verdict.split("-", 1)[-1].strip() if "-" in verdict else verdict
      if parsed is None:
        self.state.push(
            f"  [#f0c674]⚖[/] [bold white]{lane.name:<11}[/] [#f0c674]Critic gave no clear verdict — defaulting to #1:[/] [white]\"{rich_escape(reason[:36])}\"[/]"
        )
      else:
        self.state.push(
            f"  [#f0c674]⚖[/] [bold white]{lane.name:<11}[/] [#f0c674]Blind Critic picked #{choice}:[/] [white]\"{rich_escape(reason[:44])}\"[/]"
        )

      lane.active = False
      return choice, reason

  async def run_lane(self, lane: hud.Lane, role: str) -> None:
    """Executes the verification loop for a single file lane."""
    path = resolve_lane_path(lane.name)
    with open(path) as handle:
      seed = handle.read()

    lane.loop = 1

    green = await self.test(lane, role, "proving bug")
    failure = self.last_detail
    if green:
      lane.status = "no flaw reproduced"
      return
    if self.expired():
      return

    base, best_passed = seed, lane.passed

    while not self.expired() and lane.loop <= MAX_LANE_LOOPS:
      minimal = await self.build(lane, "minimal", base, failure)
      if self.expired():
        return
      defensive = await self.build(lane, "defensive", base, failure)
      if self.expired():
        return

      candidates = [c for c in (minimal, defensive) if c]
      if not candidates:
        lane.loop += 1
        continue

      if len(candidates) == 1:
        winner = candidates[0]
      else:
        ordered = candidates[:]
        random.Random(f"{lane.name}:{lane.loop}").shuffle(ordered)
        choice, _ = await self.critique(lane, ordered[0], ordered[1])
        winner = ordered[choice - 1]
        if self.expired():
          return

      with open(path, "w") as handle:
        handle.write(winner)

      if await self.test(lane, role, "verifying fix"):
        lane.status = "green"
        return

      failure = self.last_detail
      if lane.passed > best_passed:
        base, best_passed = winner, lane.passed
      else:
        with open(path, "w") as handle:
          handle.write(base)
        total = lane.passed + lane.failed
        lane.passed, lane.failed = best_passed, total - best_passed
        self.state.push(
            f"  [#f0c674]↺[/] [bold white]{lane.name:<11}[/] "
            f"[#f0c674]patch made no progress — reverted, retrying from last good version[/]"
        )
      lane.loop += 1

    if lane.status != "green":
      lane.status = f"unresolved after {lane.loop - 1} loops"


def build_state(files: list[str], task: str) -> hud.SwarmState:
  state = hud.SwarmState(task_label=task)
  state.lanes = [hud.Lane(name=f) for f in files]
  return state


async def render_forever(state: hud.SwarmState, live) -> None:
  while True:
    try:
      live.update(hud.render(state))
    except Exception:  # pylint: disable=broad-except
      pass
    await asyncio.sleep(1 / 12)


def snapshot() -> None:
  """Renders a static preview of the HUD layout."""
  state = hud.SwarmState(
      task_label="Audit & patch 3 vulnerable modules (auth.py, billing.py, database.py)"
  )
  state.show("cloud", "budget", "lanes", "focus", "footer")
  state.lanes_visible = 3
  state.task_typed = state.task_label
  state.step1_typed = "done"
  state.cloud_note = "done"
  state.cloud_status = "planned"
  state.cloud_plan_summary = "auth.py→Access Audit · billing.py→Payment Audit · database.py→Query Defense"
  state.frontier_tokens = 87
  state.local_tokens = 3_323
  state.frontier_idle_since = time.monotonic() - 42
  state.lanes = [
      hud.Lane("auth.py", role="CWE-798 Secret", loop=1, status="green", passed=2, failed=0, tokens=1_060, tok_s=16.4),
      hud.Lane("billing.py", role="CWE-362 Lock", loop=1, status="green", passed=2, failed=0, tokens=1_190, tok_s=14.9, active=True),
      hud.Lane("database.py", role="CWE-89 SQLi", loop=1, status="green", passed=2, failed=0, tokens=1_073, tok_s=15.2),
  ]
  state.focus_name = "database.py"
  state.focus_role = "blind critic"
  for line in [
      "  [#c586f0]✔[/] [bold #c586f0]CLOUD    [/] [#c586f0]Gemini spent 87 tokens and is now IDLE. It will not be called again.[/]",
      "  [#4dd0e1]▸[/] [bold #4dd0e1]HANDOFF  [/] [#4dd0e1]3 × Gemma 4 26B now running the verification loop locally — no network calls.[/]",
      "  [#ff6b81]✗[/] [bold white]billing.py [/] [#ff6b81]test failed: balance drift: 10 debits, final balance 80.00[/]",
      "  [#4dd0e1]▸[/] [bold white]billing.py [/] [#4dd0e1]Builder A (minimal) authored 20-line patch (15 tok/s)[/]",
      "  [#4dd0e1]▸[/] [bold white]billing.py [/] [#4dd0e1]Builder B (defensive) authored 28-line patch (14 tok/s)[/]",
      "  [#f0c674]⚖[/] [bold white]billing.py [/] [#f0c674]Blind Critic picked #2:[/] [white]\"Mutex prevents the race condition.\"[/]",
      "  [#5ddba4]✔[/] [bold white]billing.py [/] [#5ddba4]adversarial test suite green (2/2 passed)[/]",
  ]:
    state.focus_lines.append(line)
  state.focus_partial = ""
  state.footer = "all 3 lanes passed verification — 0 cloud tokens spent on execution"

  state.finished = True
  hud.console.print(hud.render(state))


async def type_into(setter, text: str, cps: float = 75.0) -> None:
  delay = 1.0 / cps
  for i in range(1, len(text) + 1):
    setter(text[:i] + "▌")
    await asyncio.sleep(delay)
  setter(text)


async def opening_sequence(
    state: hud.SwarmState,
    plan_future: "asyncio.Future",
    task: str,
    files: list[str],
) -> tuple[list[dict], int, str]:
  """Progressively reveals HUD panels while awaiting the Cloud Architect blueprint."""
  cm = state.cloud_model

  await type_into(lambda s: setattr(state, "task_typed", s), task, cps=95)
  await asyncio.sleep(0.12)

  await type_into(
      lambda s: setattr(state, "step1_typed", s),
      "sending AST signatures…",
      cps=85,
  )
  await type_into(
      lambda s: setattr(state, "cloud_note", s),
      f"uplink payload: {len(files)} AST skeletons (imports + defs) · 0 bytes of bodies/secrets",
      cps=115,
  )
  await asyncio.sleep(0.18)

  state.show("budget")
  await asyncio.sleep(0.35)

  state.show("lanes")
  for lane in state.lanes:
    state.lanes_visible += 1
    lane.status = "idle · no mandate yet"
    await asyncio.sleep(0.24)
  await asyncio.sleep(0.15)

  state.show("focus")
  await asyncio.sleep(0.15)
  state.push(
      f"  [{CLOUD}]⚡[/] [bold {CLOUD}]UPLINK   [/] [{CLOUD}]→ {cm}  ·  {len(files)} AST skeletons (imports + defs)  ·  0 bytes of bodies/secrets[/]"
  )
  await asyncio.sleep(0.28)
  state.push(
      f"  [{CLOUD}]⟳[/] [bold {CLOUD}]AWAITING [/] [{CLOUD}]{cm} is diagnosing CWE classes, fix strategies & API invariants…[/]"
  )

  frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
  waited_from = time.monotonic()
  index = 0
  while not plan_future.done():
    state.focus_partial = (
        f"{frames[index % len(frames)]} network round-trip in flight… "
        f"{time.monotonic() - waited_from:.1f}s"
    )
    index += 1
    await asyncio.sleep(0.08)
  state.focus_partial = ""

  plan, frontier_tokens, note = await plan_future

  await asyncio.sleep(0.22)
  by_file = {item["file"]: item for item in plan}
  for lane in state.lanes:
    item = by_file.get(lane.name, {})
    lane.role = item.get("role", "")
    lane.strategy = item.get("strategy", "")
    lane.invariant = item.get("invariant", "")
    lane.status = "mandate received"
    state.push(
        f"  [{CLOUD}]←[/] [bold {CLOUD}]MANDATE  [/] [white]{lane.name:<12}[/]"
        f" [{CLOUD}]→ \"{rich_escape(lane.role)}\"[/] [dim]→ {rich_escape(lane.strategy[:58])}[/]"
    )
    await asyncio.sleep(0.32)

  state.cloud_status = "planned"
  state.frontier_tokens = frontier_tokens
  state.cloud_called = not note
  state.cloud_skip_reason = note
  state.frontier_idle_since = time.monotonic()
  state.cloud_plan_summary = "  ·  ".join(
      f"{item['file']} → {item.get('role', '')} ({item.get('strategy', '')})"
      for item in plan
  )
  await asyncio.sleep(0.2)
  if state.cloud_called:
    state.push(
        f"  [{CLOUD}]✔[/] [bold {CLOUD}]CLOUD    [/] [{CLOUD}]{cm} spent ~{frontier_tokens} tokens on the blueprint and is now IDLE.[/]"
    )
  else:
    state.push(
        f"  [#ff6b81]![/] [bold #ff6b81]NO CLOUD [/] [#ff6b81]{rich_escape(note)} — built-in offline blueprint used instead.[/]"
    )

  await asyncio.sleep(0.22)
  state.footer = note or (
      "Step 2 running: the cloud is idle from here on — every remaining token is local and free."
  )
  state.show("footer")
  await asyncio.sleep(0.28)
  state.push(
      f"  [{LOCAL_C}]▸[/] [bold {LOCAL_C}]HANDOFF  [/] [{LOCAL_C}]{len(state.lanes)} × {state.local_model_long} take over the verification loop — offline.[/]"
  )
  for lane in state.lanes:
    lane.status = "starting verification"
  await asyncio.sleep(0.35)

  return plan, frontier_tokens, note


def parse_cli_args(argv: list[str] | None = None):
  """Parses command-line arguments."""
  import argparse  # pylint: disable=import-outside-toplevel

  parser = argparse.ArgumentParser(
      prog="hybrid_orchestrator",
      description=(
          "Gemini 3.8 Flash (Cloud Architect) + Gemma 4 (Local Adversarial Swarm). "
          "Run with no arguments for the 3-file security demo, or pass --files and "
          "--test-cmd to audit & patch your own Python modules."
      ),
  )
  parser.add_argument(
      "--minimal",
      action="store_true",
      help="Run the linear headless quickstart instead of the full Rich HUD.",
  )
  parser.add_argument(
      "--snapshot",
      action="store_true",
      help="Render a static HUD snapshot and exit.",
  )
  parser.add_argument(
      "--files",
      nargs="+",
      metavar="PATH",
      help="One or more Python files to audit and patch in-place.",
  )
  parser.add_argument(
      "--test-cmd",
      default="",
      metavar="CMD",
      help=(
          "Custom shell command to verify patches (e.g. 'pytest tests/test_app.py'). "
          "Must exit 0 when all tests pass."
      ),
  )
  parser.add_argument(
      "--task",
      default="",
      metavar="DESC",
      help="High-level task description sent to the Cloud Architect.",
  )
  return parser.parse_args(argv)


def configure_target_files(args) -> tuple[list[str], str]:
  """Configures target files and test command from parsed CLI arguments."""
  global FILE_PATHS, CUSTOM_TEST_CMD  # pylint: disable=global-statement
  CUSTOM_TEST_CMD = (args.test_cmd or "").strip()
  if args.files:
    FILE_PATHS = {}
    files: list[str] = []
    for raw_path in args.files:
      abs_path = os.path.abspath(raw_path)
      if not os.path.isfile(abs_path):
        raise SystemExit(f"Target file not found: {raw_path}")
      name = os.path.basename(abs_path)
      FILE_PATHS[name] = abs_path
      files.append(name)
    task = args.task or (
        f"Audit & patch security and concurrency flaws in ({', '.join(files)})"
    )
    return files, task

  FILE_PATHS = {}
  os.makedirs(OUT_DIR, exist_ok=True)
  reset_workspace()
  files = sorted(VULNERABLE)
  task = args.task or (
      "Audit & patch 3 vulnerable modules (auth.py, billing.py, database.py)"
  )
  return files, task


async def main() -> int:
  args = parse_cli_args()
  if args.snapshot:
    snapshot()
    return 0
  if args.minimal:
    import quickstart_minimal  # pylint: disable=import-outside-toplevel

    return await quickstart_minimal.run_minimal_workflow(args)

  configure_isolated_litert_context()
  if os.environ.get("DEMO_VERBOSE") != "1":
    logging.getLogger().setLevel(logging.ERROR)

  model_path = resolve_model_path()
  checkpoint.require_valid(model_path)

  files, task = configure_target_files(args)

  gemma = LiteRTAgentConfig(
      model_path=model_path,
      max_context_tokens=8192,
      system_instructions="You are a terse senior security engineer.",
      capabilities=CapabilitiesConfig(enabled_tools=[]),
  )
  cloud_cfg = LocalAgentConfig(
      system_instructions="You are a terse orchestrator. Reply with JSON only.",
      capabilities=CapabilitiesConfig(enabled_tools=[]),
  )

  from rich.live import Live  # pylint: disable=import-outside-toplevel

  print("Warming up the local model and cloud session...", flush=True)
  async with Agent(gemma) as agent, Agent(cloud_cfg) as manager:
    try:
      await (await agent.chat("Reply OK")).text()
    except Exception:  # pylint: disable=broad-except
      pass
    agent.conversation.clear_history()

    hud.console.clear()

    state = build_state(files, task)
    state.cloud_model = cloud_model_label()
    state.local_model, state.local_model_long = local_model_labels(model_path)
    state.cloud_status = "calling"
    state.show("cloud")

    with Live(
        hud.render(state),
        console=hud.console,
        refresh_per_second=12,
        screen=False,
        transient=False,
    ) as live:
      painter = asyncio.create_task(render_forever(state, live))
      try:
        plan_future = asyncio.ensure_future(
            plan_with_gemini(task, files, manager=manager)
        )
        await opening_sequence(state, plan_future, task, files)

        deadline = time.monotonic() + DEMO_SECONDS
        swarm = Swarm(state, agent, deadline)
        await asyncio.gather(
            *(swarm.run_lane(lane, lane.role) for lane in state.lanes)
        )
      finally:
        painter.cancel()

      state.finished = True
      if all(lane.status == "green" for lane in state.lanes):
        state.footer = "all lanes passed the adversarial suite — 0 cloud tokens spent on execution"
      else:
        state.footer = (
            f"stopped after the {DEMO_SECONDS:.0f}s budget — raise it with "
            "DEMO_SECONDS=1800 ./run.sh"
        )
      try:
        live.update(hud.render(state))
      except Exception:  # pylint: disable=broad-except
        pass

  return 0


if __name__ == "__main__":
  sys.exit(asyncio.run(main()))
