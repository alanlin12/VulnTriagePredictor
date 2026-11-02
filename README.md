# VulnTriagePredictor

Predict whether a newly published CVE will be **exploited in the wild** (added to CISA's
[Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog
within 365 days) using only information that is public **when the CVE is published**, and rank
vulnerabilities better than CVSS severity does.

> **Status:** data pipeline in progress. Downloading raw data and flattening NVD into one row per
> CVE work; the KEV join, labels, splits, and models are next.

## Quick reference

| Task | Command |
|---|---|
| Download KEV + all NVD feeds | `python3 src/ingest.py` |
| Build the flat NVD table | `python3 src/build_dataset.py` |
| Look up specific CVEs | `python3 src/build_dataset.py --show CVE-2021-44228 CVE-2016-20017` |
| See a script's options | `python3 src/ingest.py --help`, `python3 src/build_dataset.py --help` |

## Project layout

```
src/
  ingest.py          download dated snapshots of KEV + NVD
  build_dataset.py   flatten NVD records into one row per CVE (or --show a few)
data.nosync/         all data (gitignored; ".nosync" keeps it out of iCloud)
  raw/kev/           kev_<download date>.json
  raw/nvd/           nvdcve-2.0-<CVE year>_<download date>.json.gz
  processed/         nvd.parquet
```

## Setup

Requires Python 3.10+.

```bash
python3 -m pip install pandas pyarrow
```

## Usage

### 1. Download the raw data

```bash
python3 src/ingest.py
```

Downloads the KEV catalog and NVD's 2.0 yearly feeds for 2002 through the current year (~260 MB)
into `data.nosync/raw/`. NVD groups CVEs by **ID year**, and the `2002` feed also holds CVE-1999 to
CVE-2001. Old IDs are sometimes published years later, so every year is downloaded.

| Option | Effect |
|---|---|
| `--years 2023 2024` | only download these NVD years (useful for testing) |
| `--force` | re-download files that already exist for today's date |

- **Snapshots:** each file is named with its download date, so every run on a new day is a separate
  snapshot. Later steps always read the newest one.
- **Safe to re-run:** files that already exist are skipped.
- **No half-written files:** downloads go to a `.part` file and are renamed only when complete.

Check that every NVD file is intact:

```bash
for f in data.nosync/raw/nvd/*.gz; do gzip -t "$f" && echo "OK  $f" || echo "BAD $f"; done
```

### 2. Build the flat NVD table

```bash
python3 src/build_dataset.py
```

Reads the newest snapshot of each year's NVD feed, skips `Rejected` CVEs, and writes one row per
CVE (about 400,000) to `data.nosync/processed/nvd.parquet`. Takes about a minute.

| Column | Meaning |
|---|---|
| `cve_id` | CVE identifier |
| `source` | the CNA (organization) that filed the CVE |
| `published` | NVD publication date (datetime) |
| `status` | NVD analysis status |
| `description` | English description |

Inspect the result:

```bash
python3 -c "import pandas as pd; df = pd.read_parquet('data.nosync/processed/nvd.parquet'); print(df.shape); print(df.head())"
```

### Look up specific CVEs

Print the dataset row for one or more CVEs without running the full build. Nothing is written.

```bash
python3 src/build_dataset.py --show CVE-2021-44228 CVE-2016-20017
```

```
cve_id       CVE-2021-44228
source       security@apache.org
published    2021-12-10T10:15:09.143
status       Analyzed
description  Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, ...
```

IDs are case-insensitive, each year's file is loaded only once, and unknown IDs print `not found`.

## Data sources

| Source | Role | Link |
|---|---|---|
| NVD (CVE 2.0 yearly feeds) | features | <https://nvd.nist.gov/vuln/data-feeds> |
| CISA KEV | label (exploited, and when) | <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> |

## Method rules

- **Only use what was known at publication.** NVD records are edited afterwards: reference tags,
  CISA's SSVC assessment, and the `cisa*` fields are added later and must never be used as features.
- **Split by time, not at random.** The modeling window starts at KEV's launch (2021-11-03);
  earlier exploits were backfilled into KEV late.
- **A CVE is only labeled once its full 365-day horizon has passed** before the KEV snapshot date.

## Roadmap

- [x] Download dated KEV + NVD snapshots (2002 onward)
- [x] Flatten NVD into one row per CVE (identity and description fields)
- [x] `--show` lookup for individual CVEs
- [ ] Add CVSS, CWE, and vendor/product fields
- [ ] Join KEV and build the 365-day label (SQL, DuckDB)
- [ ] Time-based train / validation / test splits
- [ ] CVSS baselines, then logistic regression and gradient boosting
- [ ] Compare against EPSS
- [ ] Command-line triage tool

## License

MIT
