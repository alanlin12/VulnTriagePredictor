import argparse
import datetime as dt
import pathlib

import duckdb

from build_dataset import H, PROCESSED, RAW, newest

# Half-open ranges on NVD `published`: start <= published < end.
SPLITS = {
    "train": ("2021-11-03", "2024-01-01"),
    "val":   ("2024-01-01", "2025-01-01"),
    "test":  ("2025-01-01", "2026-01-01"),
}


def scalar(con: duckdb.DuckDBPyConnection, query: str):
    return con.execute(query).fetchall()[0][0]


def load_kev(con: duckdb.DuckDBPyConnection, path: pathlib.Path) -> dt.date:
    src = f"read_json('{path}')"
    snapshot = scalar(con, f"SELECT dateReleased::DATE FROM {src}")
    con.sql(f"""
        CREATE OR REPLACE TABLE kev AS
        SELECT v.cveID AS cve_id, min(v.dateAdded::DATE) AS kev_date   -- min() guards against duplicates
        FROM (SELECT unnest(vulnerabilities) AS v FROM {src})
        GROUP BY v.cveID
    """)
    return snapshot


def split_case() -> str:
    """SQL CASE mapping `published` to a split name, built from SPLITS so dates live in one place."""
    whens = "\n".join(
        f"WHEN published >= '{start}' AND published < '{end}' THEN '{name}'"
        for name, (start, end) in SPLITS.items()
    )
    return f"CASE {whens} ELSE NULL END"


def label(con: duckdb.DuckDBPyConnection, nvd_path: pathlib.Path, snapshot: dt.date) -> None:
    """Create table `labeled`: every NVD column plus in_kev, kev_date, days_to_kev, y, labelable, split.

    LEFT JOIN keeps the ~99.5% of CVEs that never reach KEV (they are the negatives).
    days_to_kev can be negative (CISA listed it before NVD published) - those count as y = 1.
    """
    con.sql(f"""
        CREATE OR REPLACE TABLE labeled AS
        SELECT n.*,
               k.kev_date,
               k.kev_date IS NOT NULL                                      AS in_kev,
               datediff('day', n.published::DATE, k.kev_date)              AS days_to_kev,
               coalesce(datediff('day', n.published::DATE, k.kev_date) <= {H}, false)::INT AS y,
               n.published::DATE + INTERVAL ({H}) DAY <= DATE '{snapshot}' AS labelable,
               {split_case()}                                              AS split
        FROM read_parquet('{nvd_path}') n
        LEFT JOIN kev k USING (cve_id)
    """)


def write(con: duckdb.DuckDBPyConnection) -> None:
    """Write labeled.parquet (all rows, for exploration) and one parquet per split (labelable rows only)."""
    PROCESSED.mkdir(parents=True, exist_ok=True)
    con.sql(f"COPY labeled TO '{PROCESSED / 'labeled.parquet'}' (FORMAT parquet)")
    for name in SPLITS:
        con.sql(f"""COPY (SELECT * FROM labeled WHERE split = '{name}' AND labelable ORDER BY published)
                    TO '{PROCESSED / f'{name}.parquet'}' (FORMAT parquet)""")


def report(con: duckdb.DuckDBPyConnection, snapshot: dt.date, kev_path: pathlib.Path) -> None:
    """Print a sanity table so silent mistakes (0 positives, wrong date range, bad join) show up."""
    print(f"KEV snapshot: {snapshot}  ({kev_path.name}, {scalar(con, 'SELECT count(*) FROM kev'):,} entries)")
    unmatched = scalar(con, "SELECT count(*) FROM kev WHERE cve_id NOT IN (SELECT cve_id FROM labeled)")
    print(f"KEV CVEs with no NVD row: {unmatched}")
    print(con.execute("""
        SELECT split,
               count(*) FILTER (labelable)                   AS rows,
               sum(y) FILTER (labelable)                     AS positives,
               round(100 * avg(y) FILTER (labelable), 3)     AS pct_pos,
               min(published)::DATE                          AS first_published,
               max(published) FILTER (labelable)::DATE       AS last_labelable,
               count(*) FILTER (NOT labelable)               AS dropped_window_open
        FROM labeled WHERE split IS NOT NULL
        GROUP BY split ORDER BY first_published
    """).df().to_string(index=False))


def run(kev_path: pathlib.Path | None = None) -> None:
    """Whole label step; pipeline.py calls this."""
    kev_path = kev_path or newest(RAW / "kev", "kev_*.json")
    con = duckdb.connect()
    snapshot = load_kev(con, kev_path)
    label(con, PROCESSED / "nvd.parquet", snapshot)
    write(con)
    report(con, snapshot, kev_path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kev", type=pathlib.Path, default=None,
                        help="KEV snapshot to label with (default: newest in raw/kev)")
    run(parser.parse_args().kev)


if __name__ == "__main__":
    main()
