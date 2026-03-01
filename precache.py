"""
precache.py — Pre-download and cache chart files for the last N versions of each repo.

Usage:
    python3 precache.py              # cache last 20 versions per chart
    python3 precache.py --n 10       # cache last 10 versions per chart
    python3 precache.py --repo argo-cd  # only one chart
    python3 precache.py --dry-run    # show what would be cached, don't download
"""

import os
import io
import sys
import tarfile
import argparse
import sqlite3
import requests
import logging
from datetime import datetime
from packaging.version import Version, InvalidVersion

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s  %(levelname)-7s  %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger(__name__)

DATABASE = os.path.join(os.path.dirname(__file__), 'helm_tracker.db')

KEY_FILES = [
    'values.yaml', 'Chart.yaml', 'Chart.lock',
    'templates/NOTES.txt', 'README.md',
]


# ── DB ────────────────────────────────────────────────────────────────────────

def get_conn():
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn


# ── Helpers ───────────────────────────────────────────────────────────────────

def sort_versions(versions):
    def key(v):
        try:
            return Version(v.lstrip('v'))
        except InvalidVersion:
            return Version('0.0.0')

    return sorted(versions, key=key, reverse=True)


def safe_get(url, timeout=60):
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r
    except Exception as e:
        log.warning(f"  GET failed: {url} → {e}")
        return None


def extract_chart_files(chart_url, chart_name):
    r = safe_get(chart_url)
    if not r:
        return {}
    try:
        buf = io.BytesIO(r.content)
        files = {}
        with tarfile.open(fileobj=buf, mode='r:gz') as tf:
            for member in tf.getmembers():
                parts = member.name.split('/', 1)
                rel = parts[1] if len(parts) > 1 else member.name
                if not rel:
                    continue
                is_key = any(rel == kf or rel.startswith('templates/') for kf in KEY_FILES)
                if is_key or rel in KEY_FILES:
                    try:
                        f = tf.extractfile(member)
                        if f:
                            files[rel] = f.read().decode('utf-8', errors='replace')
                    except Exception:
                        pass
        return files
    except Exception as e:
        log.warning(f"  Extract failed: {chart_url} → {e}")
        return {}


# ── Core ──────────────────────────────────────────────────────────────────────

def precache_repo(conn, repo_name, n, dry_run):
    repo = conn.execute("SELECT * FROM repos WHERE name=?", (repo_name,)).fetchone()
    if not repo:
        log.error(f"Repo '{repo_name}' not found in DB")
        return

    # Get versions sorted newest-first
    rows = conn.execute(
        "SELECT version, chart_url FROM chart_versions WHERE repo_name=? ORDER BY rowid DESC",
        (repo_name,)
    ).fetchall()

    if not rows:
        log.warning(f"  [{repo_name}] No versions in DB — run a sync first")
        return

    # Sort properly by semver
    version_map = {r['version']: r['chart_url'] for r in rows}
    sorted_vers = sort_versions(list(version_map.keys()))
    target_vers = sorted_vers[:n]

    log.info(f"[{repo_name}]  {len(target_vers)} versions to check (latest: {target_vers[0] if target_vers else '?'})")

    cached = 0
    downloaded = 0
    skipped = 0

    for version in target_vers:
        chart_url = version_map.get(version)

        # Check if release notes are cached
        ver_row = conn.execute("SELECT release_notes FROM chart_versions WHERE repo_name=? AND version=?",
                               (repo_name, version)).fetchone()
        if not ver_row or ver_row['release_notes'] is None:
            log.info(f"  ↓ {version:20s}  caching GitHub release notes...")
            # Trigger app.py's endpoint to fetch and cache the notes in the DB
            port = os.environ.get('PORT', 5000)
            safe_get(f"http://127.0.0.1:{port}/api/repos/{repo_name}/release-notes/{version}")

        # Check if already cached
        existing = conn.execute(
            "SELECT COUNT(*) as cnt FROM chart_files WHERE repo_name=? AND version=?",
            (repo_name, version)
        ).fetchone()['cnt']

        if existing > 0:
            log.info(f"  ✓ {version:20s}  already cached ({existing} files)")
            cached += 1
            continue

        if not chart_url:
            log.warning(f"  ✗ {version:20s}  no chart_url in DB, skipping")
            skipped += 1
            continue

        if dry_run:
            log.info(f"  ~ {version:20s}  would download: {chart_url}")
            continue

        log.info(f"  ↓ {version:20s}  downloading...")
        files = extract_chart_files(chart_url, repo['chart_name'])

        if not files:
            log.warning(f"  ✗ {version:20s}  download failed or empty")
            skipped += 1
            continue

        for fname, content in files.items():
            conn.execute("""
                         INSERT
                         OR IGNORE INTO chart_files (repo_name, version, filename, content)
                VALUES (?, ?, ?, ?)
                         """, (repo_name, version, fname, content))
        conn.commit()

        log.info(f"  ✓ {version:20s}  cached {len(files)} files")
        downloaded += 1


    log.info(
        f"[{repo_name}]  done — "
        f"{cached} already cached, {downloaded} downloaded, {skipped} skipped"
    )
    return cached, downloaded, skipped


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Pre-cache Helm chart files')
    parser.add_argument('--n', type=int, default=20, help='Number of versions to cache per chart (default: 20)')
    parser.add_argument('--repo', type=str, default=None, help='Only cache a specific repo by name')
    parser.add_argument('--dry-run', action='store_true', help="Show what would be downloaded without doing it")
    args = parser.parse_args()

    if not os.path.exists(DATABASE):
        log.error(f"Database not found at {DATABASE}")
        log.error(
            "Make sure you're running this from the app directory, or that the app has been started at least once.")
        sys.exit(1)

    conn = get_conn()

    if args.repo:
        repos = [args.repo]
    else:
        repos = [r['name'] for r in conn.execute("SELECT name FROM repos ORDER BY name").fetchall()]

    log.info(f"Precaching last {args.n} versions for {len(repos)} repo(s){' [DRY RUN]' if args.dry_run else ''}")
    log.info("=" * 60)

    total_cached = total_downloaded = total_skipped = 0
    start = datetime.now()

    for repo_name in repos:
        result = precache_repo(conn, repo_name, args.n, args.dry_run)
        if result:
            c, d, s = result
            total_cached += c
            total_downloaded += d
            total_skipped += s
        log.info("")

    elapsed = (datetime.now() - start).total_seconds()
    log.info("=" * 60)
    log.info(
        f"Complete in {elapsed:.1f}s — "
        f"{total_cached} already cached, "
        f"{total_downloaded} newly downloaded, "
        f"{total_skipped} skipped"
    )
    conn.close()


if __name__ == '__main__':
    main()
