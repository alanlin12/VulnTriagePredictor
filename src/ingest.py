"""Download raw snapshots: CISA KEV (labels) + NVD CVE 2.0 yearly feeds (features).

    python src/ingest.py                    # KEV + NVD 2017..this year
    python src/ingest.py --years 2023 2024  # only some NVD years
"""

import argparse
import datetime as dt
import pathlib
import shutil
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "data.nosync" / "raw"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz" # Sorted by year

def fetch(url: str, dest: pathlib.Path, force: bool = False) -> None:
    # Skip if the destination path is something that is already downloaded
    if dest.exists() and not force:
        print(f'Skipping {dest.name} - Already Exists in the Path')
        return
    
    # Checking to see if the folder exists + downloading into a temporary file
    dest.parent.mkdir(parents=True, exist_ok=True) 
    tmp = dest.with_name(dest.name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-triage-research"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as f: 
        shutil.copyfileobj(resp, f)
    
    # Rename temporary file to the real file
    tmp.rename(dest)

    print(f"saved {dest.relative_to(ROOT)} ({dest.stat().st_size / 1e6:.1f} MB)")
        

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--years", type=int, nargs="*",
                        default=list(range(2017, dt.date.today().year + 1)))
    parser.add_argument("--force", action="store_true", help="re-download today's files")
    args = parser.parse_args()

    today = dt.date.today().isoformat()                # "2026-10-29"
    fetch(KEV_URL, RAW / "kev" / f"kev_{today}.json", args.force)
    for year in args.years:
        fetch(NVD_URL.format(year=year),
            RAW / "nvd" / f"nvdcve-2.0-{year}_{today}.json.gz", args.force)


if __name__ == "__main__":
    main()