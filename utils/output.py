"""
Output layer: rich terminal table + CSV file writer.

Neither function knows anything about how data was collected —
they only consume List[InterfaceResult].
"""

import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from models.interface import InterfaceResult

logger = logging.getLogger(__name__)
console = Console()

# CSV column order
CSV_FIELDS = [
    "hostname",
    "device_ip",
    "platform",
    "interface_name",
    "mac_address",
    "ipv4_address",
    "ipv6_addresses",
    "zone",
    "error",
]


# ── Terminal output ──────────────────────────────────────────────────────────

def print_table(results: List[InterfaceResult]) -> None:
    """Render results to the terminal as a rich table."""
    if not results:
        console.print("[yellow]No results to display.[/yellow]")
        return

    table = Table(
        title="Interface Inventory",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        highlight=True,
        expand=False,
    )

    table.add_column("Hostname",         style="bold white",   no_wrap=True)
    table.add_column("Device IP",        style="white",        no_wrap=True)
    table.add_column("Platform",         style="dim white",    no_wrap=True)
    table.add_column("Interface",        style="bright_blue",  no_wrap=True)
    table.add_column("MAC Address",      style="yellow",       no_wrap=True)
    table.add_column("IPv4 Address",     style="green",        no_wrap=True)
    table.add_column("IPv6 Address(es)", style="cyan",         no_wrap=False)
    table.add_column("Zone",             style="white",        no_wrap=True)
    table.add_column("Status",           style="white",        no_wrap=True)

    for r in results:
        status = Text("✓", style="green") if not r.has_error else Text(f"✗ {r.error}", style="red")
        table.add_row(
            r.hostname,
            r.device_ip,
            r.platform,
            r.interface_name,
            r.mac_address,
            r.ipv4_address,
            r.ipv6_display,
            r.zone,
            status,
        )

    console.print()
    console.print(table)
    _print_summary(results)


def _print_summary(results: List[InterfaceResult]) -> None:
    total_devices = len({(r.hostname, r.device_ip) for r in results})
    total_ifaces  = sum(1 for r in results if not r.has_error)
    total_errors  = sum(1 for r in results if r.has_error)

    console.print(
        f"\n[bold]Summary:[/bold] "
        f"[white]{total_devices} device(s)[/white]  |  "
        f"[green]{total_ifaces} interface(s)[/green]  |  "
        f"[red]{total_errors} error(s)[/red]"
    )


# ── CSV output ───────────────────────────────────────────────────────────────

def write_csv(results: List[InterfaceResult], output_dir: str = "./output") -> str:
    """
    Write results to a timestamped CSV file.
    Returns the full path of the written file.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out_path / f"interface_inventory_{timestamp}.csv"

    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for r in results:
            writer.writerow({
                "hostname":       r.hostname,
                "device_ip":      r.device_ip,
                "platform":       r.platform,
                "interface_name": r.interface_name,
                "mac_address":    r.mac_address,
                "ipv4_address":   r.ipv4_address,
                "ipv6_addresses": r.ipv6_display,
                "zone":           r.zone,
                "error":          r.error or "",
            })

    logger.info("CSV written: %s", filename)
    console.print(f"\n[bold green]CSV saved:[/bold green] {filename}")
    return str(filename)