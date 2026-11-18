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

"""Rich terminal HUD for Antigravity Hybrid Orchestrator."""

from collections import deque
from dataclasses import dataclass, field
import os
import time

from rich.console import Console, Group
from rich.layout import Layout
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

WIDTH = 100
HEIGHT = 28

CLOUD = "#c586f0"
LOCAL = "#4dd0e1"
GOOD = "#5ddba4"
BAD = "#ff6b81"
WARN = "#f0c674"
DIM = "#6c7086"

TASK_SIZE = 1
GEMINI_FULL_SIZE = 4
BUDGET_SIZE = 4
GEMMA_STREAM_ROWS = 8
FOOTER_SIZE = 5


def _make_console() -> Console:
  force = os.environ.get("DEMO_FORCE_TTY") == "1"
  return Console(
      width=WIDTH,
      height=HEIGHT,
      highlight=False,
      force_terminal=True if force else None,
      force_interactive=False if force else None,
  )


console = _make_console()


@dataclass
class Lane:
  """State for one on-device Gemma 4 agent lane."""

  name: str
  role: str = ""
  strategy: str = ""
  invariant: str = ""
  loop: int = 0
  status: str = "queued"
  passed: int = 0
  failed: int = 0
  tokens: int = 0
  tok_s: float = 0.0
  active: bool = False


@dataclass
class SwarmState:
  """Shared display state updated by the orchestrator."""

  lanes: list[Lane] = field(default_factory=list)
  task_label: str = "Audit & patch 3 vulnerable modules (auth.py, billing.py, database.py)"

  cloud_model: str = "Gemini 3.8 Flash"
  local_model: str = "Gemma 4 26B"
  local_model_long: str = "Gemma 4 26B · on-device"

  visible: set = field(default_factory=set)
  lanes_visible: int = 0
  task_typed: str = ""
  step1_typed: str = ""
  cloud_note: str = ""

  cloud_status: str = "calling"
  cloud_plan_summary: str = ""
  cloud_called: bool = True
  cloud_skip_reason: str = ""
  frontier_tokens: int = 0
  local_tokens: int = 0
  frontier_idle_since: float | None = None
  focus_name: str = ""
  focus_role: str = ""
  focus_lines: deque = field(default_factory=lambda: deque(maxlen=6))
  focus_partial: str = ""
  footer: str = ""
  finished: bool = False
  started_at: float = field(default_factory=time.monotonic)
  extra_cloud_calls: int = 0

  def show(self, *names: str) -> None:
    self.visible.update(names)

  def push(self, line: str) -> None:
    self.focus_lines.append(line)
    self.focus_partial = ""

  @property
  def elapsed_clock(self) -> str:
    seconds = int(time.monotonic() - self.started_at)
    return f"{seconds // 60}:{seconds % 60:02d}"

  @property
  def idle_clock(self) -> str:
    if self.frontier_idle_since is None:
      return "0:00"
    seconds = int(time.monotonic() - self.frontier_idle_since)
    return f"{seconds // 60}:{seconds % 60:02d}"

  @property
  def local_share(self) -> float:
    total = self.frontier_tokens + self.local_tokens
    return (self.local_tokens / total) if total else 0.0


def _task_banner(state: SwarmState) -> Text:
  banner = Text(" ")
  banner.append(" ANTIGRAVITY HYBRID ORCHESTRATOR ", style=f"bold black on {CLOUD}")
  banner.append("  TASK: ", style="bold white")
  banner.append(state.task_typed, style="white")
  return banner


def _gemini_panel(state: SwarmState) -> Panel:
  rows = []

  if state.step1_typed:
    row = Text("  ")
    if state.cloud_status == "calling":
      row.append("⚡ DISPATCH: ", style=f"bold {CLOUD}")
      row.append(state.step1_typed, style="white")
    elif not state.cloud_called:
      row.append("! NO CLOUD CALL: ", style=f"bold {BAD}")
      row.append(f"{state.cloud_skip_reason} — using built-in offline plan", style="white")
    else:
      row.append("✔ PLAN READY: ", style=f"bold {GOOD}")
      row.append(f"Sent AST signatures (~{state.frontier_tokens} tok, 0 bodies/secrets) → ", style="white")
      row.append(f"⏸ GEMINI IDLE ({state.idle_clock})", style=f"bold {CLOUD}")
    rows.append(row)
  else:
    wait_row = Text("  ")
    wait_row.append(f"⚡ Connecting to {state.cloud_model} (Cloud Architect)…", style=f"bold {CLOUD}")
    rows.append(wait_row)

  if state.cloud_note:
    note = Text("  ")
    if state.cloud_status == "calling":
      note.append(state.cloud_note, style=DIM)
    else:
      note.append("Blueprint → ", style=f"bold {CLOUD}")
      note.append(state.cloud_plan_summary, style="white")
    rows.append(note)

  if state.cloud_status == "calling":
    status_badge = f"[bold {CLOUD}]⚡ PLANNING[/]"
  elif not state.cloud_called:
    status_badge = f"[bold {BAD}]! SKIPPED[/]"
  else:
    status_badge = f"[bold {GOOD}]✔ PLANNED[/] [dim]·[/] [bold {CLOUD}]⏸ IDLE[/]"
  return Panel(
      Group(*rows),
      title=(
          f"[bold {CLOUD}]◆ {state.cloud_model.upper()} — CLOUD ARCHITECT[/]  "
          f"[dim](Google Cloud · AST signatures only, 0 code bodies)[/]  {status_badge}"
      ),
      border_style=CLOUD,
      padding=(0, 1),
  )


def _split_bar(state: SwarmState, width: int = 92) -> Text:
  total = state.frontier_tokens + state.local_tokens
  if total <= 0:
    return Text("  " + "░" * width, style=DIM)

  cloud_cells = int(round((state.frontier_tokens / total) * width))
  cloud_cells = max(1, min(width, cloud_cells)) if state.frontier_tokens > 0 else 0

  bar = Text("  ")
  bar.append("█" * cloud_cells, style=CLOUD)
  bar.append("█" * (width - cloud_cells), style=LOCAL)
  return bar


def _budget_panel(state: SwarmState) -> Panel:
  total = state.frontier_tokens + state.local_tokens
  cloud_pct = (state.frontier_tokens / total * 100) if total else 0.0
  local_pct = 100.0 - cloud_pct if total else 0.0

  tag = f"idle {state.idle_clock}" if state.cloud_status == "planned" else "planning…"

  legend = Text("  ")
  legend.append("■ ", style=CLOUD)
  legend.append(f"{state.cloud_model.upper()}: ", style=f"bold {CLOUD}")
  legend.append(f"{state.frontier_tokens:>4,} tok ({cloud_pct:>4.1f}%) · {tag:<10}", style="white")
  legend.append("   ")
  legend.append("■ ", style=LOCAL)
  legend.append(f"{state.local_model.upper()}: ", style=f"bold {LOCAL}")
  legend.append(f"{state.local_tokens:>5,} tok ({local_pct:>4.1f}%) · ", style="white")
  legend.append("local", style=f"bold {GOOD}")

  return Panel(
      Group(_split_bar(state), legend),
      title=(
          "[bold white]TOKEN SPLIT[/]  "
          f"[dim]([bold {CLOUD}]■ {state.cloud_model}[/] in Cloud  vs.  [bold {LOCAL}]■ {state.local_model}[/] On-Device)[/]"
      ),
      border_style=DIM,
      padding=(0, 1),
  )


def _gemma_panel(state: SwarmState) -> Panel:
  rows = []
  for lane in state.lanes[: state.lanes_visible]:
    row = Text("  ")
    if lane.status == "green":
      row.append("✔", style=f"bold {GOOD}")
    elif lane.status.startswith("unresolved"):
      row.append("✗", style=f"bold {BAD}")
    elif lane.status == "no flaw reproduced":
      row.append("!", style=f"bold {WARN}")
    elif lane.active:
      row.append("●", style=f"bold {LOCAL}")
    else:
      row.append("•", style=DIM)

    row.append(f" {lane.name:<12}", style="bold white" if lane.active else "white")
    role_str = f"[{lane.role}]" if lane.role else ""
    row.append(f"{role_str:<19}", style=DIM)
    row.append(f"loop {lane.loop}  ", style=DIM)

    if lane.status == "green":
      status_style = GOOD
    elif lane.status.startswith("unresolved"):
      status_style = BAD
    elif lane.status == "no flaw reproduced":
      status_style = WARN
    else:
      status_style = LOCAL if lane.active else DIM
    row.append(f"{lane.status:<21} ", style=status_style)
    row.append(
        f"tests: ✔ {lane.passed} ✗ {lane.failed}  ",
        style=GOOD if lane.passed and not lane.failed else (BAD if lane.failed else DIM),
    )
    row.append(f"{lane.tok_s:>4.0f} tok/s", style=LOCAL if lane.tok_s > 0 else DIM)
    rows.append(row)

  if "focus" in state.visible:
    stream_title = (
        f"[bold {LOCAL}]LIVE ON-DEVICE STREAM[/] · [bold white]{rich_escape(state.focus_name)}[/] [dim]({rich_escape(state.focus_role)})[/]"
        if state.focus_name
        else f"[bold {LOCAL}]LIVE ON-DEVICE STREAM[/] [dim](prove bug → 2 builders → blind critic → re-run suite)[/]"
    )
    rows.append(Rule(title=stream_title, style=LOCAL))
    for line in state.focus_lines:
      rows.append(Text.from_markup(line))
    if state.focus_partial:
      live = Text("  ")
      live.append(state.focus_partial, style="white")
      live.append("▌", style=f"bold {LOCAL}")
      rows.append(live)

  title = (
      f"[bold {LOCAL}]◈ {state.local_model.upper()} — ON-DEVICE WORKFORCE[/]  "
      f"[dim](3 × {state.local_model_long} · Private · no cloud calls)[/]"
  )
  return Panel(
      Group(*rows) if rows else Text(""),
      title=title,
      border_style=LOCAL,
      padding=(0, 1),
  )


def _footer_panel(state: SwarmState) -> Panel:
  if not state.finished:
    line = Text("  ")
    line.append(state.footer or "Running local Gemma 4 verification loop…", style="white")

    how = Text("  ")
    how.append(
        "Per file: reproduce the bug → Builder A vs B → blind critic → re-run the suite.",
        style=DIM,
    )

    green = sum(1 for lane in state.lanes if lane.status == "green")
    live = Text("  ")
    live.append(f"elapsed {state.elapsed_clock}", style=DIM)
    live.append("   ·   ", style=DIM)
    live.append(f"lanes green {green}/{len(state.lanes) or 3}", style=GOOD if green else DIM)
    live.append("   ·   ", style=DIM)
    live.append(f"Gemma 4 tokens {state.local_tokens:,}", style=LOCAL)
    live.append("   ·   ", style=DIM)
    live.append(f"extra Gemini calls {state.extra_cloud_calls}", style=CLOUD)

    return Panel(
        Group(line, how, live),
        title="[dim]ORCHESTRATION STATUS[/]",
        border_style=DIM,
        padding=(0, 1),
    )

  loops = sum(lane.loop for lane in state.lanes)
  tests = sum(lane.passed for lane in state.lanes)
  total_lanes = len(state.lanes)
  green_lanes = sum(1 for lane in state.lanes if lane.status == "green")
  no_flaw = sum(1 for lane in state.lanes if lane.status == "no flaw reproduced")
  all_green = bool(state.lanes) and green_lanes == total_lanes

  big = Text("  ")
  if all_green:
    big.append(
        f"✔ ALL {total_lanes} FILES PATCHED & VERIFIED GREEN "
        f"({tests}/{tests} adversarial tests passing across {loops} loops)",
        style=f"bold {GOOD}",
    )
  elif no_flaw == total_lanes and total_lanes:
    big.append(
        "! NO FLAW REPRODUCED — the seed workspace was already clean",
        style=f"bold {WARN}",
    )
  else:
    unresolved = total_lanes - green_lanes - no_flaw
    parts = []
    if unresolved:
      parts.append(f"{unresolved} still failing after retries")
    if no_flaw:
      parts.append(f"{no_flaw} never reproduced a flaw")
    summary = f"✗ {green_lanes}/{total_lanes} FILES VERIFIED GREEN"
    if parts:
      summary += " — " + ", ".join(parts)
    big.append(summary, style=f"bold {BAD}")

  cost = Text("  ")
  cost.append(f"◆ {state.cloud_model}: ", style=f"bold {CLOUD}")
  cost.append(f"~{state.frontier_tokens:,} tok (planned once, then idle)", style="white")
  cost.append(f"   ◈ {state.local_model}: ", style=f"bold {LOCAL}")
  cost.append(f"~{state.local_tokens:,} tok (on-device)", style="white")

  punch = Text("  ")
  if not state.cloud_called:
    punch.append(
        "Note: no cloud call was made, so this run is entirely on-device.",
        style=f"bold {WARN}",
    )
  else:
    punch.append(
        f"~{state.local_share * 100:.1f}% on-device. Sent to {state.cloud_model}: "
        "AST signatures only — no bodies or literals.",
        style=f"bold {WARN}",
    )

  if all_green and state.cloud_called:
    title = f"[bold {GOOD}]✔ RUN COMPLETE — GEMINI + GEMMA HYBRID ORCHESTRATION SUCCEEDED[/]"
    border = GOOD
  elif all_green:
    title = f"[bold {WARN}]RUN COMPLETE — BUT NO CLOUD CALL WAS MADE[/]"
    border = WARN
  else:
    title = f"[bold {BAD}]RUN FINISHED WITH ISSUES — SEE BELOW[/]"
    border = BAD

  return Panel(
      Group(big, cost, punch),
      title=title,
      border_style=border,
      padding=(0, 1),
  )


def render(state: SwarmState) -> Layout:
  """Renders the 28-row progressive HUD layout."""
  sections: list[Layout] = []
  used = 0

  def add(renderable, name: str, size: int) -> None:
    nonlocal used
    sections.append(Layout(renderable, name=name, size=size))
    used += size

  if "cloud" in state.visible:
    add(_task_banner(state), "task", TASK_SIZE)
    gemini_rows = 1 + bool(state.cloud_note)
    add(_gemini_panel(state), "cloud", 2 + gemini_rows)
  if "budget" in state.visible:
    add(_budget_panel(state), "budget", BUDGET_SIZE)
  if "lanes" in state.visible:
    lane_rows = max(1, state.lanes_visible)
    stream_rows = GEMMA_STREAM_ROWS if "focus" in state.visible else 0
    add(_gemma_panel(state), "gemma", 2 + lane_rows + stream_rows)
  if "footer" in state.visible:
    add(_footer_panel(state), "footer", FOOTER_SIZE)

  if used < HEIGHT:
    sections.append(Layout(Text(" "), name="filler", size=HEIGHT - used))

  root = Layout()
  root.split_column(*sections)
  return root


def payoff(state: SwarmState) -> Panel:
  return _footer_panel(state)
