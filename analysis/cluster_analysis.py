#!/usr/bin/env python3
"""
Cluster Analysis — Attacker Behaviour Profiling via K-Means
===========================================================
Applies K-Means clustering to enriched honeypot event features to
segment attackers into behavioural profiles (e.g., credential stuffer,
port scanner, exploit dropper, cryptominer).

Usage:
    python cluster_analysis.py --input ../data/enriched_ips.csv --clusters 5
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from loguru import logger
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

# Human-readable labels for cluster archetypes (review after first run)
CLUSTER_LABELS = {
    0: "Credential Stuffer",
    1: "Port Scanner / Recon Bot",
    2: "Exploit Dropper",
    3: "Cryptominer Installer",
    4: "Multi-Stage Attacker",
}

FEATURE_COLS = [
    "abuse_score",
    "vt_malicious",
    "shodan_ports_count",   # derived below
    "event_count",          # derived below
    "unique_ports_targeted",
    "failed_logins",
    "successful_logins",
    "commands_executed",
    "files_downloaded",
]


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "shodan_ports" in df.columns:
        df["shodan_ports_count"] = (
            df["shodan_ports"].fillna("").apply(lambda x: len(x.split(",")) if x else 0)
        )
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0
    df[FEATURE_COLS] = df[FEATURE_COLS].fillna(0)
    return df


def run_kmeans(df: pd.DataFrame, n_clusters: int) -> tuple[pd.DataFrame, KMeans, StandardScaler]:
    feat = prepare_features(df)
    X = feat[FEATURE_COLS].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    feat["cluster"] = km.fit_predict(X_scaled)
    feat["cluster_label"] = feat["cluster"].map(
        lambda c: CLUSTER_LABELS.get(c, f"Cluster {c}")
    )
    return feat, km, scaler


def plot_pca_clusters(df: pd.DataFrame, output_dir: Path) -> None:
    X = df[FEATURE_COLS].fillna(0).values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    pca = PCA(n_components=2)
    coords = pca.fit_transform(X_scaled)

    df2 = df.copy()
    df2["pca_x"] = coords[:, 0]
    df2["pca_y"] = coords[:, 1]

    fig, ax = plt.subplots(figsize=(10, 7))
    colours = plt.cm.tab10.colors
    for cluster_id, grp in df2.groupby("cluster"):
        label = CLUSTER_LABELS.get(int(cluster_id), f"Cluster {cluster_id}")
        ax.scatter(
            grp["pca_x"], grp["pca_y"],
            c=[colours[int(cluster_id) % len(colours)]],
            label=label, alpha=0.65, s=20,
        )
    ax.set_title("Attacker Behaviour Clusters (PCA Projection)", fontsize=13, fontweight="bold")
    ax.set_xlabel(f"PC1 ({pca.explained_variance_ratio_[0]*100:.1f}% variance)")
    ax.set_ylabel(f"PC2 ({pca.explained_variance_ratio_[1]*100:.1f}% variance)")
    ax.legend(loc="best", fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    out = output_dir / "cluster_pca.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    logger.info("PCA cluster plot saved to %s", out)


def main() -> None:
    parser = argparse.ArgumentParser(description="K-Means attacker behaviour clustering")
    parser.add_argument("--input",    default="../data/enriched_ips.csv")
    parser.add_argument("--output",   default="../report/figures/")
    parser.add_argument("--clusters", type=int, default=5, help="Number of K-Means clusters")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.input)
    logger.info("Loaded %d rows from %s", len(df), args.input)

    df_clustered, km, scaler = run_kmeans(df, args.clusters)
    plot_pca_clusters(df_clustered, output_dir)

    # Save cluster assignments
    out_csv = Path(args.input).parent / "clustered_ips.csv"
    df_clustered.to_csv(out_csv, index=False)
    logger.info("Cluster assignments saved to %s", out_csv)

    # Cluster summary
    summary = (
        df_clustered.groupby("cluster_label")[FEATURE_COLS]
        .mean()
        .round(2)
        .to_dict(orient="index")
    )
    summary_path = output_dir / "cluster_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info("Cluster summary saved to %s", summary_path)


if __name__ == "__main__":
    main()
