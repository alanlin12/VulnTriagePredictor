"""Description text -> normalized text -> TF-IDF -> k-NN "exploited neighbors" score.

    python src/text_features.py            # k = 10
    python src/text_features.py --k 25
    python src/text_features.py --explain CVE-2024-3400 CVE-2023-4966   # show who voted, no rebuild

Reads train/val/test.parquet (made by label.py), writes text_knn.parquet: one row per CVE with
    knn_score       weighted share of its nearest earlier CVEs already listed in KEV
    n_neighbors     how many neighbors voted
    neighbors       their cve_ids, most similar first
    neighbor_sims   cosine similarity of each neighbor
    neighbor_votes  True if that neighbor was already in KEV the day this CVE was published
Leakage rules:
  - the vectorizer is fit on TRAIN descriptions only; val/test are only transformed
  - neighbors are CVEs (from any split) published strictly BEFORE the query CVE, so a CVE never
    counts itself or same-timestamp siblings, and every split gets equally fresh neighbors.
    (Letting train CVEs use any other train CVE gave train PR-AUC 0.28 vs val 0.09: same-batch
    siblings vote for each other, which would teach a downstream model to over-trust knn_score.
    Searching train only made val/test neighbors stale: val PR-AUC fell from 0.16 in Q1 to 0.07 in Q4.)
  - a neighbor votes "exploited" only if CISA had ALREADY listed it in KEV before the day the query
    CVE was published. Its final label y is never used, so no label from val or test is read here:
    an earlier val/test CVE contributes only its description and a KEV listing that was public then.
  - test PR-AUC is never printed here; test is scored once, at the end.
"""
import argparse
import re

import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import average_precision_score

from build_dataset import PROCESSED

SPLIT_NAMES = ("train", "val", "test")

# Patterns replaced with a placeholder token, so "foo 2.3.1" and "foo 4.0" look alike.
URL     = re.compile(r"https?://\S+")
CVE_ID  = re.compile(r"\bcve-\d{4}-\d{4,}\b")           # descriptions that cite other CVEs
VERSION = re.compile(r"\bv?\d+(\.\d+)+[a-z0-9.-]*\b")   # 2.3.1, v2.3.1, 10.0.19041.1, 1.2.3-rc1
SPACES  = re.compile(r"\s+")


def load_splits() -> dict[str, pd.DataFrame]:
    """Read the three split parquets into {name: DataFrame} with only the columns used here."""
    cols = ["cve_id", "published", "description", "y", "kev_date"]
    return {name: pd.read_parquet(PROCESSED / f"{name}.parquet", columns=cols).reset_index(drop=True)
            for name in SPLIT_NAMES}


def normalize(text: pd.Series) -> pd.Series:
    """Clean descriptions before vectorizing. Same function for every split.

    URLs go first because they often contain version-like strings.
    """
    return (text.fillna("").str.lower()
                .str.replace(URL, " url ", regex=True)
                .str.replace(CVE_ID, " cveid ", regex=True)
                .str.replace(VERSION, " ver ", regex=True)
                .str.replace(SPACES, " ", regex=True)
                .str.strip())


def fit_vectorizer(train_text: pd.Series) -> TfidfVectorizer:
    """Fit TF-IDF on TRAIN text only. Rows come out L2-normalized, so cosine similarity = dot product."""
    vec = TfidfVectorizer(stop_words="english", min_df=2, max_df=0.5,
                          ngram_range=(1, 2), sublinear_tf=True)
    return vec.fit(train_text)


def knn_score(X: sp.csr_matrix, time: np.ndarray, kev: np.ndarray, k: int,
              chunk: int = 256) -> tuple[np.ndarray, np.ndarray, list[np.ndarray], list[np.ndarray]]:
    """For every CVE: similarity-weighted share of its k nearest EARLIER CVEs that were already in KEV.

    X     L2-normalized TF-IDF rows, so X @ X.T is cosine similarity
    time  publication time of each row, sorted ascending
    kev   day each row was added to KEV (NaT = never)

    Returns (score, n_neighbors, neighbor_rows, neighbor_sims).
    n_neighbors is how many neighbors actually voted: fewer than k for the very first CVEs (little
    history) or when few earlier CVEs share any words, more than k when several are tied with the k-th.
    neighbor_rows[i] / neighbor_sims[i] list row i's neighbors (row numbers into X), most similar first.
    """
    assert (time[1:] >= time[:-1]).all(), "rows must be sorted by published"
    # Rows are time-sorted, so "published before row i" is a prefix: rows [0, cutoff[i]).
    cutoff = np.searchsorted(time, time, side="left")
    day = time.astype("datetime64[D]")

    score = np.zeros(X.shape[0])
    used = np.zeros(X.shape[0], dtype=int)
    empty = np.array([], dtype=int)
    nbr_rows: list[np.ndarray] = [empty] * X.shape[0]
    nbr_sims: list[np.ndarray] = [np.array([])] * X.shape[0]
    for start in range(0, X.shape[0], chunk):
        rows = slice(start, start + chunk)
        width = cutoff[rows].max()                                 # no row in this chunk can see past here
        if width == 0:
            continue                                               # the very first CVEs: no history
        sim = (X[rows] @ X[:width].T).toarray()                    # (chunk, width) cosine similarities
        sim[np.arange(width)[None, :] >= cutoff[rows, None]] = -1.0   # not published before this row
        kk = min(k, width)
        kth = -np.partition(-sim, kk - 1, axis=1)[:, kk - 1:kk]    # k-th largest similarity in each row
        # Keep the k most similar, plus anything tied with the k-th (identical template descriptions
        # are common), so the score never depends on which tied CVE happens to be picked.
        w = np.where((sim >= kth) & (sim > 0), sim, 0.0)           # sim <= 0: masked out, or no shared words
        known = kev[None, :width] < day[rows, None]                # already in KEV that day (NaT -> False)
        score[rows] = (w * known).sum(1) / np.maximum(w.sum(1), 1e-9)
        used[rows] = (w > 0).sum(1)
        for r in range(w.shape[0]):                                # keep the voters, for inspection
            cols = np.flatnonzero(w[r])
            cols = cols[np.argsort(-w[r, cols], kind="stable")]
            nbr_rows[start + r], nbr_sims[start + r] = cols, w[r, cols]
    return score, used, nbr_rows, nbr_sims


def run(k: int = 10) -> pd.DataFrame:
    """Whole text step; pipeline.py calls this. Returns the written table."""
    splits = load_splits()
    vec = fit_vectorizer(normalize(splits["train"].description))      # vocabulary + IDF from TRAIN only
    print(f"TF-IDF vocabulary (train only): {len(vec.vocabulary_):,} terms")

    # One time-ordered pool: train, then val, then test (each file is sorted, and the splits don't overlap).
    pool = pd.concat([df.assign(split=name) for name, df in splits.items()], ignore_index=True)
    X = vec.transform(normalize(pool.description))
    kev = pd.to_datetime(pool.kev_date).to_numpy().astype("datetime64[D]")
    score, used, nbr_rows, nbr_sims = knn_score(X, pool.published.to_numpy(), kev, k)
    day = pool.published.to_numpy().astype("datetime64[D]")
    ids = pool.cve_id.to_numpy()
    pool["knn_score"], pool["n_neighbors"] = score, used
    pool["neighbors"] = [ids[r].tolist() for r in nbr_rows]
    pool["neighbor_sims"] = [np.round(s, 4).tolist() for s in nbr_sims]
    pool["neighbor_votes"] = [(kev[r] < day[i]).tolist() for i, r in enumerate(nbr_rows)]

    for name in ("train", "val"):                            # keep test blind until the final run
        df = pool[pool.split == name]
        print(f"{name:<5}  n={len(df):>6,}  PR-AUC={average_precision_score(df.y, df.knn_score):.3f}"
              f"  (base rate {df.y.mean():.4f})  rows with <{k} neighbors: {(df.n_neighbors < k).sum():,}")

    table = pool[["cve_id", "split", "knn_score", "n_neighbors", "neighbors", "neighbor_sims", "neighbor_votes"]]
    table.to_parquet(PROCESSED / "text_knn.parquet", index=False)
    print(f"saved {PROCESSED / 'text_knn.parquet'}")
    return table


def explain(cve_ids: list[str], width: int = 70) -> None:
    """Print each CVE's score and the neighbors that voted, read from text_knn.parquet (no recompute)."""
    knn = pd.read_parquet(PROCESSED / "text_knn.parquet").set_index("cve_id")
    info = pd.concat([pd.read_parquet(PROCESSED / f"{name}.parquet",
                                      columns=["cve_id", "published", "description", "kev_date", "y"])
                      for name in SPLIT_NAMES]).set_index("cve_id")

    for cve_id in (c.upper() for c in cve_ids):
        if cve_id not in knn.index:
            print(f"{cve_id}: not in text_knn.parquet (outside train/val/test, or not labelable yet)\n")
            continue
        q, me = knn.loc[cve_id], info.loc[cve_id]
        label = "hidden (test)" if q.split == "test" else int(me.y)       # don't peek at test labels
        print(f"{cve_id}  [{q.split}]  published {me.published:%Y-%m-%d}  "
              f"knn_score {q.knn_score:.3f}  neighbors {q.n_neighbors}  y {label}")
        print(f"  {me.description[:2 * width]}")
        print(f"  {'sim':>5}  {'vote':<4}  {'neighbor':<16}  {'published':<10}  {'in KEV':<10}  description")
        for nbr, sim, vote in zip(q.neighbors, q.neighbor_sims, q.neighbor_votes):
            n = info.loc[nbr]
            kev = "" if pd.isna(n.kev_date) else f"{n.kev_date:%Y-%m-%d}"
            print(f"  {sim:>5.3f}  {'YES' if vote else '-':<4}  {nbr:<16}  {n.published:%Y-%m-%d}  "
                  f"{kev:<10}  {n.description[:width]}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--k", type=int, default=10, help="neighbors per CVE")
    parser.add_argument("--explain", nargs="+", metavar="CVE_ID",
                        help="print these CVEs' neighbors from the saved file instead of rebuilding it")
    args = parser.parse_args()
    if args.explain:
        explain(args.explain)
    else:
        run(args.k)


if __name__ == "__main__":
    main()
