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

"""Headless CLI quickstart for Antigravity Hybrid Orchestrator.

Run the built-in 3-file demo:
    ./run.sh --minimal

Or run it on custom Python files and a test command:
    ./run.sh --minimal --files path/to/module.py --test-cmd "pytest path/to/test_module.py"
"""

import asyncio
import random
import sys

from google.antigravity import Agent, CapabilitiesConfig, LiteRTAgentConfig

import hybrid_orchestrator as gc
from runtime_compat import configure_isolated_litert_context

MAX_LOOPS = 3


def one_line(text: str, limit: int = 70) -> str:
  """Formats a string onto a single truncated line for console logs."""
  flat = " ".join(text.split())
  return flat[:limit] + ("…" if len(flat) > limit else "")


async def run_minimal_workflow(args=None) -> int:
  """Executes the hybrid orchestration workflow in console mode."""
  if args is None:
    args = gc.parse_cli_args()
  configure_isolated_litert_context()
  files, task = gc.configure_target_files(args)
  model_path = gc.resolve_model_path()
  excerpts = gc.load_suite_excerpts()
  all_check_names = gc.load_suite_check_names()

  local_cfg = LiteRTAgentConfig(
      model_path=model_path,
      max_context_tokens=8192,
      system_instructions="You are a terse senior security engineer.",
      capabilities=CapabilitiesConfig(enabled_tools=[]),
  )

  print(f"[1/2] Cloud Architect ({gc.cloud_model_label()}) — AST-Skeleton Uplink (0 bytes of bodies/secrets)")
  print("      ▸ SENT TO GEMINI (extracted via ast.parse — no implementation bodies or secret literals):")
  for f in files:
    skel = gc.extract_public_skeleton(gc.resolve_lane_path(f))
    print(f"        • {skel}")
  plan, cloud_tokens, note = await gc.plan_with_gemini(task, files)
  if note:
    print(f"      ! NO CLOUD CALL MADE ({note}). Using the built-in offline blueprint:")
  else:
    print(f"      ✔ GEMINI RESPONDED WITH (~{cloud_tokens} cloud tokens; 0 source lines leaked):")
  for item in plan:
    print(f"        • {item['file']:<12} → [{item['role']}]")
    print(f"          ├─ Strategy:  {item.get('strategy', '')}")
    print(f"          └─ Invariant: {item.get('invariant', '')}")
  print("      ⏸ Cloud session is now IDLE. Handing off blueprint to local Gemma 4...\n")

  local_tokens = 0
  results: dict[str, bool] = {}
  print(f"[2/2] On-Device Verification Swarm ({gc.local_model_labels(model_path)[1]})")

  async with Agent(local_cfg) as gemma:

    async def ask(prompt: str) -> str:
      nonlocal local_tokens
      gemma.conversation.clear_history()
      reply = await (await gemma.chat(prompt)).text()
      local_tokens += gc.estimate_tokens(prompt) + gc.estimate_tokens(reply)
      return reply

    for item in plan:
      fname = item["file"]
      role = item["role"]
      strategy = item.get("strategy", "")
      invariant = item.get("invariant", "")
      module = fname.removesuffix(".py")
      path = gc.resolve_lane_path(fname)
      code = open(path).read()
      checks = excerpts.get(module, "")

      seed_passed, failed, detail = await gc.run_tests(module)
      if not failed:
        print(f"  ! {fname:<12} suite did not reproduce a flaw ({detail or 'no failures'}) — skipping")
        results[fname] = False
        continue
      print(f"  ✗ {fname:<12} [{role}] reproduced flaw: {one_line(detail)}")

      base, best_passed = code, seed_passed
      check_names = all_check_names.get(module, set())

      blueprint_block = ""
      if strategy or invariant:
        blueprint_block = (
            f"Cloud Architect Blueprint ({role}):\n"
            f"- Remediation Strategy: {strategy}\n"
            f"- Public API Invariant: {invariant}\n\n"
        )
      checks_block = (
          f"For reference only, these checks will be run against your file "
          f"from a separate test module. Do NOT include them in your "
          f"reply:\n{checks}\n\n"
          if checks
          else ""
      )

      for attempt in range(1, MAX_LOOPS + 1):
        candidates = []
        for name, instruction in gc.BUILDERS.items():
          patch = gc.strip_suite_checks(gc.extract_code(await ask(
              f"{instruction}\n\n"
              f"{blueprint_block}"
              f"File {fname}:\n{base}\n\n"
              f"{checks_block}"
              f"Current failure: {detail}\n\n"
              "Keep the module's public interface exactly as it is — the "
              "checks call these names at module level, so do not rename "
              "them, move them onto a class, or change their signatures.\n"
              f"Reply with only the contents of {fname} as one Python code "
              "block. No tests, no explanation."
          )), check_names)
          if gc.is_valid_python(patch):
            candidates.append((name, patch))
            print(f"  ▸ {fname:<12} Builder ({name}) authored {len(patch.splitlines())}-line patch")
          else:
            print(f"  ▸ {fname:<12} Builder ({name}) reply was not valid Python — discarded")

        if not candidates:
          print(f"  ↻ {fname:<12} no usable patch on attempt {attempt}/{MAX_LOOPS}")
          continue

        if len(candidates) == 1:
          winner_name, winner_code = candidates[0]
          print(f"  ⚖ {fname:<12} single valid candidate ({winner_name}) — critic skipped")
        else:
          random.Random(f"{fname}:{attempt}").shuffle(candidates)
          verdict = (await ask(
              f"Two candidate rewrites of {fname} ({role}).\n"
              f"{blueprint_block}"
              "Judge them on correctness, adherence to the Architect's "
              "strategy/invariant, and minimal risk.\n\n"
              f"Candidate 1:\n{candidates[0][1]}\n\n"
              f"Candidate 2:\n{candidates[1][1]}\n\n"
              "Reply: '1' or '2', then a dash, then under 12 words of justification."
          )).strip()
          winner_idx = gc.parse_verdict(verdict) or 1
          winner_name, winner_code = candidates[winner_idx - 1]
          print(f"  ⚖ {fname:<12} Blind Critic picked #{winner_idx} ({winner_name}): {one_line(verdict)}")

        open(path, "w").write(winner_code)
        passed, failed, detail = await gc.run_tests(module)
        if not failed:
          print(f"  ✔ {fname:<12} VERIFIED GREEN ({passed}/{passed + failed} adversarial checks passed)\n")
          results[fname] = True
          break
        print(f"  ✗ {fname:<12} still failing after attempt {attempt}/{MAX_LOOPS}: {one_line(detail)}")
        if passed > best_passed:
          base, best_passed = winner_code, passed
        else:
          open(path, "w").write(base)
          print(f"  ↺ {fname:<12} no progress — reverted to last good version")
      else:
        print(f"  ✗ {fname:<12} NOT FIXED after {MAX_LOOPS} attempts\n")
        results[fname] = False

  green = sum(1 for ok in results.values() if ok)
  total_tokens = cloud_tokens + local_tokens
  cloud_pct = (cloud_tokens / total_tokens * 100) if total_tokens else 0.0
  local_pct = (local_tokens / total_tokens * 100) if total_tokens else 0.0

  print("=" * 74)
  print(f"RUN {'COMPLETE' if green == len(plan) else 'FINISHED WITH FAILURES'} — "
        f"{green}/{len(plan)} files verified green")
  if note:
    print("NO CLOUD CALL WAS MADE — this run used the offline blueprint.")
  print(f"Token split (estimated) — Cloud: {cloud_tokens} tok ({cloud_pct:.1f}%) | "
        f"On-Device: {local_tokens:,} tok ({local_pct:.1f}%)")
  print("=" * 74)
  return 0 if green == len(plan) else 1


if __name__ == "__main__":
  sys.exit(asyncio.run(run_minimal_workflow()))
