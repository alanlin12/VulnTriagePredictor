"""Join NVD + KEV into one row per CVE -> data.nosync/processed/cves.parquet."""
import gzip
import json
import pathlib
from datetime import date
import pandas as pd
import argparse

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "data.nosync" / "raw"
PROCESSED = ROOT / "data.nosync" / "processed"
H = 365
INIT_YEAR = 2002

def newest(folder: pathlib.Path, pattern: str) -> pathlib.Path:
    match = sorted(folder.glob(pattern))
    if not match: # File not found
        raise FileNotFoundError(f"The requested file, {pattern} is not found in {folder}")
    return match[-1]

def row(cve: dict) -> dict:
    return {
        "cve_id": cve["id"],
        "source": cve["sourceIdentifier"],
        "published": cve["published"],
        "status": cve["vulnStatus"],
        "description": next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), ""),
    }

def load_year(year: int) -> list[dict]:
    path = newest(RAW / "nvd", f"nvdcve-2.0-{year}_*.json.gz")
    with gzip.open(path) as f:
        data = json.load(f)
    return [item["cve"] for item in data["vulnerabilities"]]

def show(ids: list[str]) -> None:
    """Print the row for each requested CVE, loading each year's file only once."""
    ids = [i.upper() for i in ids if i.upper().startswith("CVE-") or print(f"{i}: not a CVE ID")] # accept cve-2021-44228 too
    wanted_by_year: dict[int, set[str]] = {}
    for cve_id in ids:
        year = max(int(cve_id.split("-")[1]), INIT_YEAR)  # CVE-1999..2001 live in the 2002 file
        wanted_by_year.setdefault(year, set()).add(cve_id)

    found = {}
    for year, wanted in wanted_by_year.items():
        for cve in load_year(year):
            if cve["id"] in wanted:
                found[cve["id"]] = cve

    for cve_id in ids:
        if cve_id not in found:
            print(f"{cve_id}: not found\n")
            continue
        for key, value in row(found[cve_id]).items():
            print(f"{key:12s} {str(value)[:100]}")
        print()

def build():
    rows = []
    for yr in range(INIT_YEAR, date.today().year + 1):
        for cve in load_year(yr):
            if cve["vulnStatus"] != "Rejected":
                rows.append(row(cve))
        print(f"{yr}: {len(rows):,} rows so far")

    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"])

    PROCESSED.mkdir(parents=True, exist_ok=True)
    df.to_parquet(PROCESSED / "nvd.parquet", index=False)
    print(f"saved {len(df):,} CVEs")
    
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show", nargs="+", metavar="CVE_ID",
                        help="print the row for these CVEs instead of building the full table")
    args = parser.parse_args()

    if args.show:
        show(args.show)
    else:
        build()

if __name__ == "__main__":
    main()