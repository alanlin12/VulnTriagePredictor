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

PLACEHOLDERS = {"", "n/a", "unknown"}  # vendor values some CNAs use instead of filling it in
CVSS_FIELDS = {
    "attackVector": "cvss_attack_vector",
    "attackComplexity": "cvss_attack_complexity",
    "privilegesRequired": "cvss_privileges_required",
    "userInteraction": "cvss_user_interaction",
    "scope": "cvss_scope",
    "confidentialityImpact": "cvss_confidentiality",
    "integrityImpact": "cvss_integrity",
    "availabilityImpact": "cvss_availability",
}

def newest(folder: pathlib.Path, pattern: str) -> pathlib.Path:
    match = sorted(folder.glob(pattern))
    if not match: # File not found
        raise FileNotFoundError(f"The requested file, {pattern} is not found in {folder}")
    return match[-1]

def pick_cvss(cve: dict) -> tuple[str, dict]:
    """CVSS v3: the CNA's score first (filed at publication), then NVD's. Never CISA's (added later)."""
    metrics = cve.get("metrics", {})
    scores = metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", [])
    for name, source in (("cna", cve["sourceIdentifier"]), ("nvd", "nvd@nist.gov")):
        for m in scores:
            if m["source"] == source:
                return name, m["cvssData"]
    return "none", {}


def pick_cwe(cve: dict) -> tuple[str, str | None]:
    """(who filed it, first CWE ID): the CNA's before NVD's. NVD-CWE-noinfo / NVD-CWE-Other count as unknown."""
    weaknesses = cve.get("weaknesses", [])
    for name, source in (("cna", cve["sourceIdentifier"]), ("nvd", "nvd@nist.gov")):
        for w in weaknesses:
            if w["source"] == source:
                for d in w["description"]:
                    if d["value"].startswith("CWE-"):
                        return name, d["value"]
    return "none", None


def pick_vendor_product(cve: dict) -> tuple[str, str | None, str | None]:
    """(who filed it, vendor, product): the CNA's own values; NVD's CPE string as fallback.

    The CPE list is written by NVD analysts AFTER publication, so the source is kept ("cna" / "nvd").
    """
    for a in cve.get("affected", []):
        if a["source"] == cve["sourceIdentifier"]:
            for item in a.get("affectedData", []):
                vendor = (item.get("vendor") or "").lower()
                if vendor not in PLACEHOLDERS:
                    return "cna", vendor, (item.get("product") or "").lower() or None
    for config in cve.get("configurations", []):
        for node in config["nodes"]:
            for match in node["cpeMatch"]:
                parts = match["criteria"].split(":")   # cpe:2.3:a:vendor:product:...
                return "nvd", parts[3], parts[4]
    return "none", None, None


def english_description(cve: dict) -> str:
    """The English description ("" if there is none)."""
    for d in cve["descriptions"]:
        if d["lang"] == "en":
            return d["value"]
    return ""


def ssvc_exploitation(cve: dict) -> str | None:
    """CISA's SSVC "exploitation" value (none / poc / active), added after publication."""
    for assessment in cve.get("metrics", {}).get("ssvcV203", []):
        for option in assessment["ssvcData"]["options"]:
            if "exploitation" in option:
                return option["exploitation"]
    return None


def row(cve: dict) -> dict:
    """One CVE as a flat dict, plus leak_ columns for analysis.

    cvss_*, cwe and vendor/product each come with a *_source column: "cna" values were filed by the
    reporting organization, "nvd" values were added later by NVD analysts. NVD analyzes exploited CVEs
    first, so whether an NVD value exists at all leaks the label. at_publication() blanks them.
    """
    cvss_source, cvss = pick_cvss(cve)
    cwe_source, cwe = pick_cwe(cve)
    vendor_source, vendor, product = pick_vendor_product(cve)
    references = cve.get("references", [])

    return {
        # identity
        "cve_id":      cve["id"],
        "source":      cve["sourceIdentifier"],
        "published":   cve["published"],
        "description": english_description(cve),

        # severity (CVSS v3)
        "cvss_source": cvss_source,
        "cvss_score":  cvss.get("baseScore"),
        **{column: cvss.get(key) for key, column in CVSS_FIELDS.items()},

        # weakness type and affected product
        "cwe_source":    cwe_source,
        "cwe":           cwe,
        "vendor_source": vendor_source,
        "vendor":        vendor,
        "product":       product,

        # added AFTER publication: analysis only, never features
        "leak_status":            cve["vulnStatus"],   # NVD's analysis state today; "Analyzed" tracks KEV
        "leak_ssvc_exploitation": ssvc_exploitation(cve),
        "leak_exploit_ref":       any("Exploit" in r.get("tags", []) for r in references),
        "leak_cisa_kev":          "cisaExploitAdd" in cve,
    }

def at_publication(df: pd.DataFrame) -> pd.DataFrame:
    """Copy of df holding only what the CNA filed: NVD-added CVSS / CWE / vendor become missing, leak_ columns go.

    Use this view for anything a model or baseline sees. Label columns (y, kev_date, ...) are left alone.
    """
    out = df.drop(columns=[c for c in df.columns if c.startswith("leak_")])
    out.loc[out.cvss_source != "cna", ["cvss_score", *CVSS_FIELDS.values()]] = None
    out.loc[out.cwe_source != "cna", "cwe"] = None
    out.loc[out.vendor_source != "cna", ["vendor", "product"]] = None
    return out


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
        r = row(found[cve_id])
        width = max(len(key) for key in r)               # longest column name sets the alignment
        for key, value in r.items():
            print(f"{key:<{width}}  {str(value)[:100]}")
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