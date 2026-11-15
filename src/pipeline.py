"""Run the data pipeline in order: ingest -> build -> label -> text.

    python src/pipeline.py                      # build -> label -> text (offline, uses raw files on disk)
    python src/pipeline.py --from ingest        # download fresh NVD + KEV first
    python src/pipeline.py --from label         # only relabel + rescore (nvd.parquet already built)
    python src/pipeline.py --to label           # stop after labeling
    python src/pipeline.py --kev data.nosync/raw/kev/kev_2026-11-15.json   # pin the label snapshot

Each step reads the previous step's files, so starting midway reuses what is on disk:
    ingest  -> raw/nvd/*.json.gz, raw/kev/*.json
    build   -> processed/nvd.parquet
    label   -> processed/labeled.parquet, train/val/test.parquet
    text    -> processed/text_knn.parquet
"""

import argparse
import pathlib
import time

import build_dataset
import ingest
import label
import text_features
from build_dataset import PROCESSED

STEPS = ("ingest", "build", "label", "text")
NEEDS = {                                   # files a step reads; checked before it runs
    "label": [PROCESSED / "nvd.parquet"],
    "text":  [PROCESSED / f"{name}.parquet" for name in label.SPLITS],
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from", dest="start", choices=STEPS, default="build")
    parser.add_argument("--to", dest="stop", choices=STEPS, default="text")
    parser.add_argument("--kev", type=pathlib.Path, default=None,
                        help="KEV snapshot for labels (default: newest in raw/kev)")
    parser.add_argument("--k", type=int, default=10, help="neighbors for the text k-NN score")
    args = parser.parse_args()

    run = {
        "ingest": lambda: ingest.run(),
        "build":  lambda: build_dataset.build(),
        "label":  lambda: label.run(args.kev),
        "text":   lambda: text_features.run(args.k),
    }
    steps = STEPS[STEPS.index(args.start): STEPS.index(args.stop) + 1]
    if not steps:
        parser.error("--from must come before --to")

    for step in steps:
        missing = [p.name for p in NEEDS.get(step, []) if not p.exists()]
        if missing:
            raise SystemExit(f"[{step}] missing {missing}: run an earlier step first (e.g. --from build)")
        print(f"\n=== {step} ===")
        t0 = time.time()
        run[step]()
        print(f"[{step}] done in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
