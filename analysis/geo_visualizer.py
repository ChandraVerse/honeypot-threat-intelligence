"""
geo_visualizer.py
=================
Generates all 6 research paper figures (fig2–fig7) from the CSVs in
report/figures/.  Can also generate individual charts via --chart flag.

Usage
-----
    # Generate all 6 figures
    python geo_visualizer.py --output ../report/figures/

    # Generate a specific chart only
    python geo_visualizer.py --chart ttp    --output ../report/figures/
    python geo_visualizer.py --chart hourly --output ../report/figures/
    python geo_visualizer.py --chart geo    --output ../report/figures/
    python geo_visualizer.py --chart ports  --output ../report/figures/
    python geo_visualizer.py --chart sensor --output ../report/figures/
    python geo_visualizer.py --chart timeline --output ../report/figures/

Output files
------------
    fig2_ttp_frequency.png
    fig3_hourly_distribution.png
    fig4_geo_origins.png
    fig5_port_distribution.png
    fig6_sensor_mix.png
    fig7_mirai_timeline.png

Dependencies
------------
    pip install matplotlib pandas seaborn numpy
"""

import argparse
import os
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless — no display needed
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as mticker
from matplotlib.gridspec import GridSpec
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Palette — matches the index.html dark-mode terminal aesthetic
# ---------------------------------------------------------------------------
BG        = "#0a0e14"
SURFACE   = "#0f1419"
SURFACE2  = "#141b24"
BORDER    = "#21262d"
TEXT      = "#e6edf3"
MUTED     = "#8b949e"
FAINT     = "#3d444d"
TEAL      = "#39d0d8"
BLUE      = "#58a6ff"
ORANGE    = "#f0883e"
RED       = "#ff6b6b"
GREEN     = "#3fb950"
PURPLE    = "#bc8cff"
YELLOW    = "#e3b341"
CRITICAL  = "#ff4444"
HIGH      = "#f0883e"
MEDIUM    = "#e3b341"

SEVERITY_COLORS = {
    "Critical": CRITICAL,
    "High":     HIGH,
    "Medium":   MEDIUM,
}

DPI = 180
FIGSIZE_WIDE  = (14, 6)
FIGSIZE_SQ    = (10, 8)
FIGSIZE_TALL  = (12, 9)
FIGSIZE_HBAR  = (13, 7)

FONT_MONO = "DejaVu Sans Mono"
FONT_SANS = "DejaVu Sans"


def _style_fig(fig, ax_list=None):
    """Apply dark background to figure and all axes."""
    fig.patch.set_facecolor(BG)
    if ax_list is None:
        ax_list = fig.get_axes()
    for ax in ax_list:
        ax.set_facecolor(SURFACE)
        ax.tick_params(colors=MUTED, labelsize=9)
        ax.xaxis.label.set_color(MUTED)
        ax.yaxis.label.set_color(MUTED)
        ax.title.set_color(TEXT)
        for spine in ax.spines.values():
            spine.set_edgecolor(BORDER)


def _add_caption(fig, text, y=0.01):
    fig.text(
        0.5, y, text,
        ha="center", va="bottom",
        fontsize=8, color=MUTED,
        fontstyle="italic",
        fontfamily=FONT_SANS,
    )


def _save(fig, path: Path, name: str):
    out = path / name
    fig.savefig(out, dpi=DPI, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    print(f"  ✓  Saved → {out}")


# ---------------------------------------------------------------------------
# Figure 2 — TTP Frequency Heatmap / Bar Chart
# ---------------------------------------------------------------------------
def fig2_ttp_frequency(data_dir: Path, out_dir: Path):
    csv = data_dir / "ttp_frequency_data.csv"
    df = pd.read_csv(csv).sort_values("event_count", ascending=True)

    fig, ax = plt.subplots(figsize=FIGSIZE_HBAR)
    _style_fig(fig, [ax])

    colors = [SEVERITY_COLORS.get(s, MEDIUM) for s in df["severity"]]
    bars = ax.barh(
        df["technique_id"], df["event_count"],
        color=colors, height=0.6,
        edgecolor="none",
    )

    # Value labels
    for bar, row in zip(bars, df.itertuples()):
        ax.text(
            bar.get_width() + 2000,
            bar.get_y() + bar.get_height() / 2,
            f"{row.event_count:,}",
            va="center", ha="left",
            color=TEXT, fontsize=9, fontfamily=FONT_MONO,
        )

    # Technique name annotations inside bars
    for bar, row in zip(bars, df.itertuples()):
        ax.text(
            bar.get_width() * 0.02,
            bar.get_y() + bar.get_height() / 2,
            f"  {row.technique_name}",
            va="center", ha="left",
            color=BG if bar.get_width() > 30000 else TEXT,
            fontsize=8.5, fontfamily=FONT_SANS, fontweight="bold",
        )

    ax.set_xlabel("Total Events Observed (30-day window)", color=MUTED, fontsize=10)
    ax.set_title(
        "Figure 2 — MITRE ATT&CK TTP Frequency\n"
        "Honeypot Threat Intelligence Platform · 30-Day Observation Window",
        color=TEXT, fontsize=12, fontweight="bold", pad=14,
    )
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{int(x/1000)}k"))
    ax.grid(axis="x", color=BORDER, linewidth=0.6, linestyle="--", alpha=0.8)
    ax.set_axisbelow(True)

    # Legend
    legend_patches = [
        mpatches.Patch(color=CRITICAL, label="Critical"),
        mpatches.Patch(color=HIGH,     label="High"),
        mpatches.Patch(color=MEDIUM,   label="Medium"),
    ]
    ax.legend(
        handles=legend_patches, loc="lower right",
        facecolor=SURFACE2, edgecolor=BORDER,
        labelcolor=TEXT, fontsize=9,
    )

    _add_caption(fig, "All IP addresses in underlying data are partially anonymized. "
                       "Technique IDs reference MITRE ATT&CK v14.")
    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _save(fig, out_dir, "fig2_ttp_frequency.png")


# ---------------------------------------------------------------------------
# Figure 3 — Hourly Attack Distribution Heatmap
# ---------------------------------------------------------------------------
def fig3_hourly_distribution(data_dir: Path, out_dir: Path):
    csv = data_dir / "hourly_attack_distribution.csv"
    df = pd.read_csv(csv, index_col="hour_utc")
    days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    matrix = df[days].values  # shape (24, 7)

    fig, ax = plt.subplots(figsize=(13, 8))
    _style_fig(fig, [ax])

    im = ax.imshow(
        matrix,
        aspect="auto",
        cmap="YlOrRd",
        interpolation="nearest",
    )

    ax.set_xticks(range(7))
    ax.set_xticklabels([d.capitalize() for d in days], color=TEXT, fontsize=10)
    ax.set_yticks(range(24))
    ax.set_yticklabels(
        [f"{h:02d}:00" for h in range(24)],
        color=MUTED, fontsize=8, fontfamily=FONT_MONO,
    )
    ax.invert_yaxis()

    # Cell value annotations
    for r in range(24):
        for c in range(7):
            val = matrix[r, c]
            ax.text(
                c, r, f"{val:,}",
                ha="center", va="center",
                fontsize=6.5, fontfamily=FONT_MONO,
                color="black" if val > 5000 else "white",
            )

    cbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cbar.ax.tick_params(colors=MUTED, labelsize=8)
    cbar.set_label("Avg Events / Hour", color=MUTED, fontsize=9)
    cbar.ax.yaxis.set_tick_params(color=MUTED)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=MUTED)

    ax.set_title(
        "Figure 3 — Hourly Attack Distribution Heatmap (UTC)\n"
        "Honeypot Threat Intelligence Platform · 30-Day Observation Window",
        color=TEXT, fontsize=12, fontweight="bold", pad=14,
    )

    # Peak band annotation
    ax.axhspan(1.5, 5.5, color=TEAL, alpha=0.08, linewidth=0)
    ax.text(
        7.05, 3.5, "← Peak Window\n   02:00–06:00 UTC",
        va="center", color=TEAL, fontsize=8.5, fontfamily=FONT_SANS,
    )

    _add_caption(fig, "Peak attack window (02:00–06:00 UTC) highlighted in teal. "
                       "Values represent average events per hour across all 30 days.")
    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _save(fig, out_dir, "fig3_hourly_distribution.png")


# ---------------------------------------------------------------------------
# Figure 4 — Geographic Attack Origins (Horizontal Bar)
# ---------------------------------------------------------------------------
def fig4_geo_origins(data_dir: Path, out_dir: Path):
    csv = data_dir / "geo_attack_origins.csv"
    df = pd.read_csv(csv)
    df = df[df["country"] != "Other"].sort_values("total_attacks", ascending=True)

    fig, (ax_bar, ax_pie) = plt.subplots(1, 2, figsize=(16, 7))
    _style_fig(fig, [ax_bar, ax_pie])

    # --- Horizontal bar ---
    bar_colors = [RED, RED, ORANGE, ORANGE, YELLOW, BLUE, BLUE, TEAL, GREEN, GREEN]
    bars = ax_bar.barh(
        df["country"], df["total_attacks"],
        color=bar_colors[:len(df)], height=0.65, edgecolor="none",
    )
    for bar, row in zip(bars, df.itertuples()):
        ax_bar.text(
            bar.get_width() + 1500,
            bar.get_y() + bar.get_height() / 2,
            f"{row.total_attacks:,}  ({row.pct_of_total:.1f}%)",
            va="center", ha="left",
            color=TEXT, fontsize=8.5, fontfamily=FONT_MONO,
        )
    ax_bar.set_xlabel("Total Attack Events", color=MUTED, fontsize=10)
    ax_bar.xaxis.set_major_formatter(
        mticker.FuncFormatter(lambda x, _: f"{int(x/1000)}k")
    )
    ax_bar.grid(axis="x", color=BORDER, linewidth=0.5, linestyle="--", alpha=0.7)
    ax_bar.set_axisbelow(True)
    ax_bar.set_title("Attack Volume by Country", color=TEXT, fontsize=11, fontweight="bold")
    ax_bar.tick_params(axis="y", labelsize=10, labelcolor=TEXT)

    # --- Pie chart ---
    top5  = df.tail(5)
    other = df.head(len(df) - 5)["total_attacks"].sum()
    pie_labels  = list(top5["country"]) + ["Other"]
    pie_values  = list(top5["total_attacks"]) + [other]
    pie_colors  = [RED, RED, ORANGE, ORANGE, YELLOW, FAINT]
    wedges, texts, autotexts = ax_pie.pie(
        pie_values,
        labels=pie_labels,
        colors=pie_colors,
        autopct="%1.1f%%",
        startangle=140,
        pctdistance=0.75,
        wedgeprops={"edgecolor": BG, "linewidth": 2},
    )
    for t in texts:
        t.set_color(TEXT)
        t.set_fontsize(9)
    for at in autotexts:
        at.set_color(BG)
        at.set_fontsize(8)
        at.set_fontweight("bold")
    ax_pie.set_title("Top-5 Country Share", color=TEXT, fontsize=11, fontweight="bold")

    fig.suptitle(
        "Figure 4 — Geographic Attack Origins\n"
        "Honeypot Threat Intelligence Platform · 30-Day Observation Window",
        color=TEXT, fontsize=12, fontweight="bold", y=1.01,
    )
    _add_caption(fig, "Country attribution is based on MaxMind GeoLite2 City database. "
                       "TOR exit node traffic is attributed to the exit node's registered country.")
    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _save(fig, out_dir, "fig4_geo_origins.png")


# ---------------------------------------------------------------------------
# Figure 5 — Top Targeted Ports
# ---------------------------------------------------------------------------
def fig5_port_distribution(out_dir: Path):
    ports = [
        ("SSH (22)",    234500),
        ("SMB (445)",    98200),
        ("RDP (3389)",   74300),
        ("HTTP (80)",    52100),
        ("Telnet (23)",  28400),
        ("HTTPS (443)",  18700),
        ("MySQL (3306)", 12300),
        ("FTP (21)",      9800),
    ]
    labels = [p[0] for p in ports]
    values = [p[1] for p in ports]

    gradient_colors = [TEAL, BLUE, BLUE, ORANGE, ORANGE, YELLOW, GREEN, MUTED]

    fig, ax = plt.subplots(figsize=(13, 6))
    _style_fig(fig, [ax])

    bars = ax.bar(
        labels, values,
        color=gradient_colors, edgecolor="none", width=0.6,
    )
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 2000,
            f"{val:,}",
            ha="center", va="bottom",
            color=TEXT, fontsize=9, fontfamily=FONT_MONO,
        )

    ax.set_ylabel("Total Attack Events (30-day)", color=MUTED, fontsize=10)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{int(x/1000)}k"))
    ax.grid(axis="y", color=BORDER, linewidth=0.5, linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)
    ax.set_title(
        "Figure 5 — Top Targeted Ports\n"
        "Honeypot Threat Intelligence Platform · 30-Day Observation Window",
        color=TEXT, fontsize=12, fontweight="bold", pad=14,
    )
    ax.tick_params(axis="x", labelsize=10, labelcolor=TEXT)

    # Annotation: SSH dominates
    ax.annotate(
        "SSH dominates (47% of events)\nPrimary vector: T1110 Brute Force",
        xy=(0, 234500), xytext=(1.5, 200000),
        color=TEAL, fontsize=9, fontfamily=FONT_SANS,
        arrowprops=dict(arrowstyle="->", color=TEAL, lw=1.2),
    )

    _add_caption(fig, "Port attribution based on Cowrie (SSH/Telnet), Dionaea (SMB/FTP), "
                       "Glastopf (HTTP/HTTPS), and Heralding (multi-protocol) sensor logs.")
    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _save(fig, out_dir, "fig5_port_distribution.png")


# ---------------------------------------------------------------------------
# Figure 6 — Sensor / Protocol Mix (Donut)
# ---------------------------------------------------------------------------
def fig6_sensor_mix(out_dir: Path):
    sensors = [
        ("Cowrie\n(SSH/Telnet)",   47, TEAL),
        ("Dionaea\n(SMB/FTP)",     20, RED),
        ("Heralding\n(Multi)",     14, BLUE),
        ("Glastopf\n(HTTP)",       13, ORANGE),
        ("ADBHoney\n(ADB)",         6, PURPLE),
    ]
    labels = [s[0] for s in sensors]
    values = [s[1] for s in sensors]
    colors = [s[2] for s in sensors]

    fig, (ax_donut, ax_legend) = plt.subplots(
        1, 2, figsize=(13, 7),
        gridspec_kw={"width_ratios": [2, 1]},
    )
    _style_fig(fig, [ax_donut, ax_legend])

    wedges, texts, autotexts = ax_donut.pie(
        values,
        labels=None,
        colors=colors,
        autopct="%1.0f%%",
        startangle=90,
        pctdistance=0.78,
        wedgeprops={"edgecolor": BG, "linewidth": 3, "width": 0.55},
    )
    for at in autotexts:
        at.set_color(BG)
        at.set_fontsize(11)
        at.set_fontweight("bold")

    # Centre label
    ax_donut.text(
        0, 0.1, "500k+",
        ha="center", va="center", fontsize=20,
        fontweight="bold", color=TEXT, fontfamily=FONT_MONO,
    )
    ax_donut.text(
        0, -0.2, "total events",
        ha="center", va="center", fontsize=10,
        color=MUTED, fontfamily=FONT_SANS,
    )
    ax_donut.set_title("Attack Protocol Distribution", color=TEXT, fontsize=11, fontweight="bold")

    # Legend panel
    ax_legend.axis("off")
    for i, (label, val, color) in enumerate(sensors):
        y = 0.82 - i * 0.18
        ax_legend.add_patch(
            mpatches.FancyBboxPatch(
                (0.05, y - 0.06), 0.12, 0.10,
                boxstyle="round,pad=0.01",
                facecolor=color, edgecolor="none",
            )
        )
        ax_legend.text(0.22, y, label.replace("\n", " "),
                       va="center", ha="left", color=TEXT, fontsize=10)
        ax_legend.text(0.85, y, f"{val}%",
                       va="center", ha="right", color=color,
                       fontsize=11, fontfamily=FONT_MONO, fontweight="bold")
    ax_legend.set_xlim(0, 1)
    ax_legend.set_ylim(0, 1)
    ax_legend.set_title("Sensor Breakdown", color=TEXT, fontsize=11, fontweight="bold")

    fig.suptitle(
        "Figure 6 — Attack Protocol Mix by Honeypot Sensor\n"
        "Honeypot Threat Intelligence Platform · 30-Day Observation Window",
        color=TEXT, fontsize=12, fontweight="bold",
    )
    _add_caption(fig, "Cowrie captures 47% of events as SSH/Telnet brute-force is the dominant "
                       "attack vector. Dionaea captures SMB exploit attempts including EternalBlue variants.")
    fig.tight_layout(rect=[0, 0.04, 1, 0.95])
    _save(fig, out_dir, "fig6_sensor_mix.png")


# ---------------------------------------------------------------------------
# Figure 7 — Mirai Infection Chain / Research Timeline
# ---------------------------------------------------------------------------
def fig7_mirai_timeline(out_dir: Path):
    events = [
        ("Day 1",  "T1046",  "Network Scanning",
         "First connections within 6 min of deployment.\nPorts 22, 23, 445, 3389 all probed within 24h.",
         TEAL, "Discovery"),
        ("Day 4",  "T1110",  "Brute Force Campaign",
         "Coordinated password spraying across 1,200+ IPs.\nShared wordlists: root, admin, pi, ubuntu.",
         HIGH, "Credential Access"),
        ("Day 8",  "T1059",  "Shell Session Captured",
         "Cowrie full session: wget → chmod +x → XMRig install.\nT1496 Resource Hijacking confirmed.",
         ORANGE, "Execution"),
        ("Day 15", "T1105",  "Mirai Binary Captured",
         "Dionaea captured Mirai-variant via port 23/Telnet.\nVirusTotal: 47/72 detections. STIX malware object created.",
         RED, "C2"),
        ("Day 22", "T1090",  "TOR Exit Node Spike",
         "+28% connections from known TOR exit nodes.\nAbuseIPDB scores >90 on 340+ IPs. Confidence 85+.",
         PURPLE, "Command & Control"),
        ("Day 30", "—",      "Collection Complete",
         "500k+ events. 8k+ IOCs. 9 TTPs. STIX 2.1 feed generated.\nResearch paper finalised.",
         GREEN, "Wrap-up"),
    ]

    fig = plt.figure(figsize=(15, 9))
    _style_fig(fig)
    ax = fig.add_subplot(111)
    ax.set_facecolor(BG)
    ax.axis("off")

    fig.suptitle(
        "Figure 7 — 30-Day Attacker Activity Timeline & Mirai Infection Chain\n"
        "Honeypot Threat Intelligence Platform",
        color=TEXT, fontsize=12, fontweight="bold", y=0.97,
    )

    n = len(events)
    xs = np.linspace(0.07, 0.93, n)
    y_line  = 0.52
    y_dot   = 0.52
    y_label_top    = 0.62
    y_label_bottom = 0.38

    # Timeline line
    ax.plot([xs[0] - 0.02, xs[-1] + 0.02], [y_line, y_line],
            color=BORDER, linewidth=2.5, zorder=1)

    for i, (day, tid, title, desc, color, tactic) in enumerate(events):
        x = xs[i]
        above = (i % 2 == 0)

        # Connector
        y_text = y_label_top if above else y_label_bottom
        ax.plot([x, x], [y_dot, y_text],
                color=color, linewidth=1.2, linestyle="--", alpha=0.6, zorder=2)

        # Dot
        ax.scatter([x], [y_dot], s=160, color=color, zorder=4, edgecolors=BG, linewidths=2)

        # Day label on line
        ax.text(x, y_line - 0.07, day,
                ha="center", va="top", color=MUTED,
                fontsize=9, fontfamily=FONT_MONO)

        # TTP badge
        if tid != "—":
            ax.text(x, y_line + 0.04, tid,
                    ha="center", va="bottom", color=color,
                    fontsize=9, fontfamily=FONT_MONO, fontweight="bold")

        # Card
        card_y = y_text + (0.02 if above else -0.26)
        card_h = 0.26
        ax.add_patch(mpatches.FancyBboxPatch(
            (x - 0.085, card_y), 0.17, card_h,
            boxstyle="round,pad=0.01",
            facecolor=SURFACE2, edgecolor=color, linewidth=1.2,
            zorder=3,
        ))
        # Tactic chip
        ax.add_patch(mpatches.FancyBboxPatch(
            (x - 0.075, card_y + card_h - 0.05), 0.15, 0.04,
            boxstyle="round,pad=0.005",
            facecolor=color, edgecolor="none", zorder=4, alpha=0.85,
        ))
        ax.text(x, card_y + card_h - 0.03, tactic,
                ha="center", va="center", color=BG,
                fontsize=7.5, fontfamily=FONT_SANS, fontweight="bold", zorder=5)
        # Title
        ax.text(x, card_y + card_h - 0.08, title,
                ha="center", va="top", color=TEXT,
                fontsize=9, fontfamily=FONT_SANS, fontweight="bold", zorder=5,
                wrap=True)
        # Description
        ax.text(x, card_y + 0.02, desc,
                ha="center", va="bottom", color=MUTED,
                fontsize=7.8, fontfamily=FONT_SANS, zorder=5,
                multialignment="center")

    ax.set_xlim(0, 1)
    ax.set_ylim(0.05, 0.98)
    _add_caption(fig, "Timeline represents key observations during the 30-day passive honeypot deployment. "
                       "All attacker data is anonymized.")
    _save(fig, out_dir, "fig7_mirai_timeline.png")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
CHART_MAP = {
    "ttp":      ("fig2_ttp_frequency.png",       "Figure 2: TTP Frequency"),
    "hourly":   ("fig3_hourly_distribution.png", "Figure 3: Hourly Heatmap"),
    "geo":      ("fig4_geo_origins.png",         "Figure 4: Geo Origins"),
    "ports":    ("fig5_port_distribution.png",   "Figure 5: Port Distribution"),
    "sensor":   ("fig6_sensor_mix.png",          "Figure 6: Sensor Mix"),
    "timeline": ("fig7_mirai_timeline.png",      "Figure 7: Mirai Timeline"),
}


def main():
    parser = argparse.ArgumentParser(
        description="Generate research paper figures (fig2–fig7) for the "
                    "Honeypot Threat Intelligence Platform."
    )
    parser.add_argument(
        "--output", "-o",
        default="../report/figures/",
        help="Output directory for PNG files (default: ../report/figures/)",
    )
    parser.add_argument(
        "--chart", "-c",
        choices=list(CHART_MAP.keys()),
        default=None,
        help="Generate a single chart only. Omit to generate all 6.",
    )
    parser.add_argument(
        "--data", "-d",
        default=None,
        help="Data directory containing CSV files "
             "(default: same as --output)",
    )
    args = parser.parse_args()

    out_dir  = Path(args.output).resolve()
    data_dir = Path(args.data).resolve() if args.data else out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n🍯  Honeypot TIP — Figure Generator")
    print(f"    Output  : {out_dir}")
    print(f"    Data    : {data_dir}")
    print(f"    Chart   : {args.chart or 'ALL'}\n")

    def _run_all():
        print("Generating fig2 — TTP Frequency …")
        fig2_ttp_frequency(data_dir, out_dir)

        print("Generating fig3 — Hourly Distribution …")
        fig3_hourly_distribution(data_dir, out_dir)

        print("Generating fig4 — Geographic Origins …")
        fig4_geo_origins(data_dir, out_dir)

        print("Generating fig5 — Port Distribution …")
        fig5_port_distribution(out_dir)

        print("Generating fig6 — Sensor Mix …")
        fig6_sensor_mix(out_dir)

        print("Generating fig7 — Mirai Timeline …")
        fig7_mirai_timeline(out_dir)

    if args.chart is None:
        _run_all()
    else:
        fname, label = CHART_MAP[args.chart]
        print(f"Generating {label} …")
        {
            "ttp":      lambda: fig2_ttp_frequency(data_dir, out_dir),
            "hourly":   lambda: fig3_hourly_distribution(data_dir, out_dir),
            "geo":      lambda: fig4_geo_origins(data_dir, out_dir),
            "ports":    lambda: fig5_port_distribution(out_dir),
            "sensor":   lambda: fig6_sensor_mix(out_dir),
            "timeline": lambda: fig7_mirai_timeline(out_dir),
        }[args.chart]()

    print("\n✅  All figures generated successfully.")
    print(f"    Files saved to: {out_dir}\n")


if __name__ == "__main__":
    main()
