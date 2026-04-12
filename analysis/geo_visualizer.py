#!/usr/bin/env python3
"""
Geo Visualizer — Attack Origin Geographic Mapping
==================================================
Produces choropleth world maps and heatmaps of attacker origin
countries/cities using enriched IP data.

Usage:
    python geo_visualizer.py --output ../report/figures/
    python geo_visualizer.py --input ../data/enriched_ips.csv --output ../report/figures/
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import plotly.express as px
from loguru import logger

plt.rcParams.update({"figure.dpi": 150, "font.family": "DejaVu Sans"})


def load_data(input_path: str) -> pd.DataFrame:
    df = pd.read_csv(input_path)
    required = {"country_code", "country_name"}
    missing  = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns in input: {missing}")
    return df


def plot_choropleth(df: pd.DataFrame, output_dir: Path) -> None:
    counts = df["country_code"].value_counts().reset_index()
    counts.columns = ["country_code", "attack_count"]
    country_names = df[["country_code", "country_name"]].drop_duplicates()
    counts = counts.merge(country_names, on="country_code", how="left")

    fig = px.choropleth(
        counts,
        locations="country_code",
        color="attack_count",
        hover_name="country_name",
        hover_data={"attack_count": True, "country_code": False},
        color_continuous_scale="YlOrRd",
        title="Honeypot Attack Origins — 30-Day Observation Window",
        labels={"attack_count": "Attack Events"},
    )
    fig.update_layout(
        geo=dict(showframe=False, showcoastlines=True, projection_type="natural earth"),
        coloraxis_colorbar=dict(title="Events"),
        margin={"r": 0, "t": 50, "l": 0, "b": 0},
    )
    out = output_dir / "choropleth_attack_origins.html"
    fig.write_html(str(out))
    out_png = output_dir / "choropleth_attack_origins.png"
    fig.write_image(str(out_png), width=1400, height=700)
    logger.info("Choropleth saved to %s", out)


def plot_top_countries_bar(df: pd.DataFrame, output_dir: Path, top_n: int = 15) -> None:
    counts = (
        df["country_name"].value_counts().head(top_n).reset_index()
    )
    counts.columns = ["country", "attacks"]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.barh(counts["country"][::-1], counts["attacks"][::-1], color="#c0392b")
    ax.bar_label(bars, padding=4, fontsize=9)
    ax.set_xlabel("Number of Attack Events")
    ax.set_title(f"Top {top_n} Attacker Countries — 30-Day Window", fontsize=14, fontweight="bold")
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    out = output_dir / "top_countries_bar.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    logger.info("Bar chart saved to %s", out)


def plot_hourly_heatmap(df: pd.DataFrame, output_dir: Path) -> None:
    if "timestamp" not in df.columns:
        logger.warning("No 'timestamp' column found; skipping hourly heatmap")
        return
    df2 = df.copy()
    df2["timestamp"] = pd.to_datetime(df2["timestamp"], utc=True, errors="coerce")
    df2 = df2.dropna(subset=["timestamp"])
    df2["hour"] = df2["timestamp"].dt.hour
    df2["day"]  = df2["timestamp"].dt.day_name()

    pivot = df2.groupby(["day", "hour"]).size().unstack(fill_value=0)
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    pivot = pivot.reindex([d for d in day_order if d in pivot.index])

    fig, ax = plt.subplots(figsize=(16, 5))
    im = ax.imshow(pivot.values, aspect="auto", cmap="YlOrRd")
    ax.set_xticks(range(24))
    ax.set_xticklabels([f"{h:02d}:00" for h in range(24)], rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)
    ax.set_title("Attack Activity Heatmap (UTC Hour × Day-of-Week)", fontsize=13, fontweight="bold")
    plt.colorbar(im, ax=ax, label="Event Count")
    plt.tight_layout()
    out = output_dir / "hourly_heatmap.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    logger.info("Heatmap saved to %s", out)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate geographic attack visualisations")
    parser.add_argument("--input",  default="../data/enriched_ips.csv", help="Enriched IP CSV")
    parser.add_argument("--output", default="../report/figures/",       help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading data from %s", args.input)
    df = load_data(args.input)
    logger.info("Loaded %d rows", len(df))

    plot_choropleth(df, output_dir)
    plot_top_countries_bar(df, output_dir)
    plot_hourly_heatmap(df, output_dir)
    logger.info("All visualisations generated in %s", output_dir)


if __name__ == "__main__":
    main()
