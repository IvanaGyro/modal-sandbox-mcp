"""Idle budget and Exit Snapshot lifecycle helpers.

Pricing snapshot: Modal Sandbox non-preemptible CPU/memory rates,
https://modal.com/pricing (verified 2026-11-16).
The budget is specifically the cost of ONE CPU core for TWO HOURS.
Actual billing can exceed estimates if resource use bursts above reservation,
regional multipliers apply, or pricing changes.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_FLOOR

CPU_CORE_USD_PER_SECOND = Decimal("0.00003942")
MEMORY_GIB_USD_PER_SECOND = Decimal("0.00000667")
REFERENCE_CORE_HOURS = Decimal("2")
IDLE_BUDGET_USD = CPU_CORE_USD_PER_SECOND * REFERENCE_CORE_HOURS * Decimal(3600)
MAX_LIFETIME_SECONDS = 24 * 3600
DEFAULT_LIFETIME_SECONDS = 24 * 3600


def idle_budget_for(cpu: float, memory_mib: int, lifetime_seconds: int) -> dict:
    """Calculate how long a CPU Sandbox may sit idle for a fixed USD budget.

    Returns both raw budget-derived timeout and effective timeout capped by
    the Sandbox lifetime; this is a *cost estimate*, not a spend hard limit.
    """
    if not 60 <= lifetime_seconds <= MAX_LIFETIME_SECONDS:
        raise ValueError("lifetime_seconds must be 60–86400")

    cpu_rate = Decimal(str(cpu)) * CPU_CORE_USD_PER_SECOND
    memory_rate = (Decimal(memory_mib) / Decimal(1024)) * MEMORY_GIB_USD_PER_SECOND
    total_rate = cpu_rate + memory_rate

    # Resource validity belongs to Modal, not the MCP. Keep this cost
    # calculation safe even when Modal will reject a resource request.
    if total_rate.is_finite() and total_rate > 0:
        calculated_seconds = max(1, int(
            (IDLE_BUDGET_USD / total_rate).to_integral_value(rounding=ROUND_FLOOR)
        ))
        effective_seconds = min(calculated_seconds, lifetime_seconds)
        estimated_idle_usd = float(total_rate * Decimal(effective_seconds))
    else:
        # Let modal.Sandbox.create report invalid CPU/RAM requests itself.
        calculated_seconds = None
        effective_seconds = lifetime_seconds
        estimated_idle_usd = None
    return {
        "idle_seconds": effective_seconds,
        "calculated_idle_seconds": calculated_seconds,
        "idle_capped_by_lifetime": (calculated_seconds is not None and
                                    effective_seconds < calculated_seconds),
        "idle_budget_usd": float(IDLE_BUDGET_USD),
        "idle_budget_basis": "2 hours of 1 Modal Sandbox CPU core (CPU-only)",
        "reserved_cpu_cores": cpu,
        "reserved_memory_mib": memory_mib,
        "estimated_cpu_usd_per_second": float(cpu_rate) if cpu_rate.is_finite() else None,
        "estimated_memory_usd_per_second": float(memory_rate) if memory_rate.is_finite() else None,
        "estimated_total_usd_per_second": float(total_rate) if total_rate.is_finite() else None,
        "estimated_idle_cost_usd": estimated_idle_usd,
        "pricing_reference": "https://modal.com/pricing",
        "pricing_as_of": "2026-11-16",
        "estimate_only": True,
        "billing_caveat": (
            "Estimates assume reserved CPU/memory and base-region pricing. "
            "Actual costs may be higher with usage bursts or regional multipliers. "
            "This controls idle duration, not total Sandbox spend."
        ),
    }


def managed_tags(cpu: float, memory_mib: int, lifetime_seconds: int,
                 persistent_workspace: bool) -> dict[str, str]:
    return {
        "mcp_managed": "1",
        "mcp_exit_snapshot": "1",
        "mcp_persistent_workspace": "1" if persistent_workspace else "0",
        "mcp_cpu_cores": str(cpu),
        "mcp_memory_mib": str(memory_mib),
        "mcp_lifetime_seconds": str(lifetime_seconds),
    }


def restored_settings(tags: dict[str, str]) -> tuple[float, int, int, bool]:
    if tags.get("mcp_managed") != "1" or tags.get("mcp_exit_snapshot") != "1":
        raise ValueError("Sandbox was not created by this MCP with Exit Snapshots")
    cpu = float(tags["mcp_cpu_cores"])
    memory_mib = int(tags["mcp_memory_mib"])
    lifetime_seconds = int(tags["mcp_lifetime_seconds"])
    persistent = tags.get("mcp_persistent_workspace") == "1"
    idle_budget_for(cpu, memory_mib, lifetime_seconds)
    return cpu, memory_mib, lifetime_seconds, persistent


def delete_exit_snapshot_of(
    sandbox, modal_api, timeout_seconds: int = 45,
    snapshot_enabled: bool | None = None,
) -> dict:
    """Delete only this Sandbox instance's Exit Snapshot, never its base Image.

    Must run after termination; failure returns an explicit *not deleted*
    status. No deletion is claimed until modal.experimental.image_delete
    succeeds.
    """
    if snapshot_enabled is None:
        snapshot_enabled = sandbox.get_tags().get("mcp_exit_snapshot") == "1"
    if not snapshot_enabled:
        return {"status": "not_enabled", "deleted": False}
    if sandbox.poll() is None:
        return {
            "status": "running", "deleted": False,
            "message": "A running Sandbox cannot have an Exit Snapshot deleted.",
        }

    try:
        snapshot = sandbox._experimental_get_exit_snapshot(timeout=timeout_seconds)
    except Exception as exc:
        return {
            "status": "not_deleted",
            "deleted": False,
            "error_type": type(exc).__name__,
            "message": "Exit Snapshot not ready or retrieval failed. It remains available until expiration.",
        }

    image_id = snapshot.object_id
    if not image_id or not image_id.startswith("im-"):
        return {"status": "not_deleted", "deleted": False,
                "message": "Modal returned an invalid Exit Snapshot Image ID"}
    try:
        modal_api.experimental.image_delete(image_id)
    except Exception as exc:
        return {"status": "not_deleted", "deleted": False,
                "image_id": image_id, "error_type": type(exc).__name__,
                "message": "Snapshot deletion failed; it may remain until expiration."}

    return {"status": "deleted", "deleted": True, "image_id": image_id}
