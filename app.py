"""
SKEW Log
Tracks SRE helm repos, compares versions, shows diffs and breaking changes.
"""

import os
import io
import re
import gzip
import tarfile
import sqlite3
import logging
import threading
import time
import difflib
import requests
import yaml
from datetime import datetime, date
from flask import Flask, jsonify, render_template, request, g
from packaging.version import Version, InvalidVersion

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
DATABASE = os.path.join(os.path.dirname(__file__), 'helm_tracker.db')

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')

# ─── Default SRE Helm Repos ─────────────────────────────────────────────────

DEFAULT_REPOS = [
    {
        "name": "cert-manager",
        "helm_repo_url": "https://charts.jetstack.io",
        "chart_name": "cert-manager",
        "github_repo": "cert-manager/cert-manager",
    },
    {
        "name": "ingress-nginx",
        "helm_repo_url": "https://kubernetes.github.io/ingress-nginx",
        "chart_name": "ingress-nginx",
        "github_repo": "kubernetes/ingress-nginx",
    },
    {
        "name": "kube-prometheus-stack",
        "helm_repo_url": "https://prometheus-community.github.io/helm-charts",
        "chart_name": "kube-prometheus-stack",
        "github_repo": "prometheus-community/helm-charts",
    },
    {
        "name": "argo-cd",
        "helm_repo_url": "https://argoproj.github.io/argo-helm",
        "chart_name": "argo-cd",
        "github_repo": "argoproj/argo-helm",
    },
    {
        "name": "external-secrets",
        "helm_repo_url": "https://charts.external-secrets.io",
        "chart_name": "external-secrets",
        "github_repo": "external-secrets/external-secrets",
    },
    {
        "name": "metrics-server",
        "helm_repo_url": "https://kubernetes-sigs.github.io/metrics-server/",
        "chart_name": "metrics-server",
        "github_repo": "kubernetes-sigs/metrics-server",
    },
    {
        "name": "velero",
        "helm_repo_url": "https://vmware-tanzu.github.io/helm-charts",
        "chart_name": "velero",
        "github_repo": "vmware-tanzu/velero",
    },
    {
        "name": "sealed-secrets",
        "helm_repo_url": "https://bitnami-labs.github.io/sealed-secrets",
        "chart_name": "sealed-secrets",
        "github_repo": "bitnami-labs/sealed-secrets",
    },
    {
        "name": "grafana",
        "helm_repo_url": "https://grafana.github.io/helm-charts",
        "chart_name": "grafana",
        "github_repo": "grafana/helm-charts",
    },
    {
        "name": "loki",
        "helm_repo_url": "https://grafana.github.io/helm-charts",
        "chart_name": "loki",
        "github_repo": "grafana/helm-charts",
    },
    {
        "name": "tempo",
        "helm_repo_url": "https://grafana.github.io/helm-charts",
        "chart_name": "tempo",
        "github_repo": "grafana/helm-charts",
    },
    {
        "name": "istio-base",
        "helm_repo_url": "https://istio-release.storage.googleapis.com/charts",
        "chart_name": "base",
        "github_repo": "istio/istio",
    },
    {
        "name": "istiod",
        "helm_repo_url": "https://istio-release.storage.googleapis.com/charts",
        "chart_name": "istiod",
        "github_repo": "istio/istio",
    },
]

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db:
        db.close()

def get_db_direct():
    """Get DB connection outside of request context."""
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_direct()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            helm_repo_url TEXT NOT NULL,
            chart_name TEXT NOT NULL,
            github_repo TEXT NOT NULL,
            latest_version TEXT,
            last_checked TEXT
        );

        CREATE TABLE IF NOT EXISTS chart_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name TEXT NOT NULL,
            version TEXT NOT NULL,
            chart_url TEXT,
            release_date TEXT,
            release_notes TEXT,
            has_breaking_changes INTEGER DEFAULT 0,
            breaking_changes_summary TEXT,
            fetched_at TEXT,
            UNIQUE(repo_name, version)
        );

        CREATE TABLE IF NOT EXISTS chart_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name TEXT NOT NULL,
            version TEXT NOT NULL,
            filename TEXT NOT NULL,
            content TEXT,
            UNIQUE(repo_name, version, filename)
        );
    """)
    # Seed default repos
    for repo in DEFAULT_REPOS:
        conn.execute("""
            INSERT OR IGNORE INTO repos (name, helm_repo_url, chart_name, github_repo)
            VALUES (?, ?, ?, ?)
        """, (repo['name'], repo['helm_repo_url'], repo['chart_name'], repo['github_repo']))
    conn.commit()
    conn.close()
    logger.info("Database initialised.")

# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def gh_headers():
    h = {'Accept': 'application/vnd.github+json'}
    if GITHUB_TOKEN:
        h['Authorization'] = f'Bearer {GITHUB_TOKEN}'
    return h

def safe_get(url, timeout=30, **kwargs):
    try:
        r = requests.get(url, timeout=timeout, **kwargs)
        r.raise_for_status()
        return r
    except Exception as e:
        logger.warning(f"GET {url} failed: {e}")
        return None

# ─── Helm Index Parsing ───────────────────────────────────────────────────────

def fetch_helm_index(helm_repo_url):
    """Fetch and parse a Helm repo index.yaml, returns dict keyed by chart name."""
    url = helm_repo_url.rstrip('/') + '/index.yaml'
    r = safe_get(url, timeout=45)
    if not r:
        return None
    try:
        # Use r.content (bytes) and decode with errors='replace' to handle
        # special characters that break yaml.safe_load on some repos (e.g. ingress-nginx)
        content = r.content.decode('utf-8', errors='replace')
        return yaml.safe_load(content)
    except Exception as e:
        logger.error(f"Failed to parse index.yaml from {url}: {e}")
        return None

def sort_versions(versions):
    """Sort semantic versions descending, best effort."""
    def key(v):
        try:
            return Version(v.lstrip('v'))
        except InvalidVersion:
            return Version('0.0.0')
    return sorted(versions, key=key, reverse=True)

def resolve_chart_url(base_url, chart_url):
    """Resolve relative or absolute chart URLs."""
    if chart_url.startswith('http'):
        return chart_url
    return base_url.rstrip('/') + '/' + chart_url.lstrip('/')

# ─── Release Notes ────────────────────────────────────────────────────────────

BREAKING_PATTERNS = [
    r'breaking[\s_-]?change', r'⚠️', r'🚨', r'migration\s+guide',
    r'incompatible', r'removed\s+support', r'deprecated\s+and\s+removed',
    r'\*\*breaking\*\*', r'## breaking', r'# breaking',
    r'action\s+required', r'requires\s+manual',
]
BREAKING_RE = re.compile('|'.join(BREAKING_PATTERNS), re.IGNORECASE)

def detect_breaking_changes(text):
    """Return (has_breaking, summary_lines)."""
    if not text:
        return False, []
    lines = text.splitlines()
    hits = []
    for i, line in enumerate(lines):
        if BREAKING_RE.search(line):
            # grab context: current line + up to 3 after
            context = lines[i:i+4]
            hits.append('\n'.join(context).strip())
    return bool(hits), hits

def fetch_github_release_notes(github_repo, version):
    """Try to get release notes from GitHub for a specific version tag."""
    tags_to_try = [version, f'v{version}', f'helm-chart-{version}',
                   f'chart-{version}']
    for tag in tags_to_try:
        url = f"https://api.github.com/repos/{github_repo}/releases/tags/{tag}"
        r = safe_get(url, headers=gh_headers())
        if r and r.status_code == 200:
            data = r.json()
            return data.get('body', '')
    # Try listing releases and finding closest match
    url = f"https://api.github.com/repos/{github_repo}/releases?per_page=50"
    r = safe_get(url, headers=gh_headers())
    if r:
        for rel in r.json():
            tag = rel.get('tag_name', '')
            if version in tag or tag.lstrip('v') == version.lstrip('v'):
                return rel.get('body', '')
    return ''

# ─── Chart Download & Extraction ─────────────────────────────────────────────

KEY_FILES = [
    'values.yaml', 'Chart.yaml', 'Chart.lock',
    'templates/NOTES.txt', 'README.md',
]

def extract_chart_files(chart_url, chart_name):
    """Download chart tarball and extract key files. Returns dict {filename: content}."""
    r = safe_get(chart_url, timeout=60)
    if not r:
        return {}
    try:
        buf = io.BytesIO(r.content)
        files = {}
        with tarfile.open(fileobj=buf, mode='r:gz') as tf:
            for member in tf.getmembers():
                # strip leading chart-name/ prefix
                parts = member.name.split('/', 1)
                rel_path = parts[1] if len(parts) > 1 else member.name
                if not rel_path:
                    continue
                # Collect key files + all templates/
                is_key = any(rel_path == kf or rel_path.startswith('templates/') for kf in KEY_FILES)
                if is_key or rel_path in KEY_FILES:
                    try:
                        f = tf.extractfile(member)
                        if f:
                            content = f.read().decode('utf-8', errors='replace')
                            files[rel_path] = content
                    except Exception:
                        pass
        return files
    except Exception as e:
        logger.error(f"Failed to extract chart from {chart_url}: {e}")
        return {}

# ─── Sync Logic ──────────────────────────────────────────────────────────────

def sync_repo(repo_name, conn=None):
    """Fetch versions from helm index for a repo, store only the latest 50."""
    close_conn = False
    if conn is None:
        conn = get_db_direct()
        close_conn = True

    row = conn.execute("SELECT * FROM repos WHERE name=?", (repo_name,)).fetchone()
    if not row:
        return False, "Repo not found"

    logger.info(f"Syncing {repo_name}...")
    index = fetch_helm_index(row['helm_repo_url'])
    if not index:
        return False, "Failed to fetch helm index"

    entries = index.get('entries', {}).get(row['chart_name'], [])
    if not entries:
        return False, f"Chart '{row['chart_name']}' not found in index"

    # Build full version list first, then take only the latest 50
    all_entries = {}
    for entry in entries:
        version = entry.get('version', '')
        if version:
            all_entries[version] = entry

    sorted_versions = sort_versions(list(all_entries.keys()))
    latest_version = sorted_versions[0] if sorted_versions else None
    # Keep only the 50 most recent — no one diffs v0.1.0 against v9.0.0
    versions_to_store = sorted_versions[:50]

    versions_added = 0
    for version in versions_to_store:
        entry = all_entries[version]
        urls = entry.get('urls', [])
        chart_url = resolve_chart_url(row['helm_repo_url'], urls[0]) if urls else None
        created = entry.get('created', '')
        if isinstance(created, datetime):
            release_date = created.isoformat()[:10]
        else:
            release_date = str(created)[:10] if created else ''

        existing = conn.execute(
            "SELECT id FROM chart_versions WHERE repo_name=? AND version=?",
            (repo_name, version)
        ).fetchone()

        if not existing:
            conn.execute("""
                INSERT OR IGNORE INTO chart_versions
                  (repo_name, version, chart_url, release_date, fetched_at)
                VALUES (?, ?, ?, ?, ?)
            """, (repo_name, version, chart_url, release_date, datetime.utcnow().isoformat()))
            versions_added += 1

    conn.execute("""
        UPDATE repos SET latest_version=?, last_checked=? WHERE name=?
    """, (latest_version, datetime.utcnow().isoformat(), repo_name))
    conn.commit()

    if close_conn:
        conn.close()

    logger.info(f"Synced {repo_name}: {versions_added} new versions stored (capped at 50), latest={latest_version}")
    return True, f"Synced: {versions_added} new versions. Latest: {latest_version}"

def check_new_releases_today():
    """Daily job: check if any new release was published today."""
    today = date.today().isoformat()
    logger.info(f"Daily release check for {today}...")
    conn = get_db_direct()
    repos = conn.execute("SELECT name FROM repos").fetchall()
    for r in repos:
        sync_repo(r['name'], conn)
        # Check if latest version was released today
        row = conn.execute(
            "SELECT version, release_date FROM chart_versions WHERE repo_name=? ORDER BY rowid DESC LIMIT 1",
            (r['name'],)
        ).fetchone()
        if row and row['release_date'] == today:
            logger.info(f"🆕 New release today: {r['name']} {row['version']}")
    conn.close()

def background_scheduler():
    """Run daily release check every 24 hours."""
    while True:
        try:
            check_new_releases_today()
        except Exception as e:
            logger.error(f"Scheduler error: {e}")
        time.sleep(86400)  # 24 hours

# ─── Diff Engine ─────────────────────────────────────────────────────────────

def build_diff(files_a, files_b, version_a, version_b):
    """Build structured diff between two chart versions."""
    all_files = sorted(set(list(files_a.keys()) + list(files_b.keys())))
    result = []
    for fname in all_files:
        content_a = files_a.get(fname, '')
        content_b = files_b.get(fname, '')
        if content_a == content_b:
            status = 'unchanged'
            diff_lines = []
        elif fname not in files_a:
            status = 'added'
            diff_lines = [f'+ {l}' for l in content_b.splitlines()]
        elif fname not in files_b:
            status = 'removed'
            diff_lines = [f'- {l}' for l in content_a.splitlines()]
        else:
            status = 'modified'
            diff = list(difflib.unified_diff(
                content_a.splitlines(keepends=True),
                content_b.splitlines(keepends=True),
                fromfile=f"{fname} ({version_a})",
                tofile=f"{fname} ({version_b})",
                lineterm='',
            ))
            diff_lines = diff

        result.append({
            'filename': fname,
            'status': status,
            'diff': diff_lines,
            'additions': sum(1 for l in diff_lines if l.startswith('+') and not l.startswith('+++')),
            'deletions': sum(1 for l in diff_lines if l.startswith('-') and not l.startswith('---')),
        })
    return result

def ensure_chart_files_cached(repo_name, version, conn):
    """Make sure chart files are in DB; download if not."""
    row = conn.execute("SELECT name, helm_repo_url, chart_name, github_repo FROM repos WHERE name=?", (repo_name,)).fetchone()
    ver_row = conn.execute(
        "SELECT chart_url FROM chart_versions WHERE repo_name=? AND version=?",
        (repo_name, version)
    ).fetchone()
    if not ver_row:
        return {}

    existing = conn.execute(
        "SELECT filename, content FROM chart_files WHERE repo_name=? AND version=?",
        (repo_name, version)
    ).fetchall()
    if existing:
        return {r['filename']: r['content'] for r in existing}

    # Download and cache
    chart_url = ver_row['chart_url']
    if not chart_url:
        return {}

    files = extract_chart_files(chart_url, row['chart_name'])
    for fname, content in files.items():
        conn.execute("""
            INSERT OR IGNORE INTO chart_files (repo_name, version, filename, content)
            VALUES (?, ?, ?, ?)
        """, (repo_name, version, fname, content))
    conn.commit()
    logger.info(f"Cached {len(files)} files for {repo_name}@{version}")
    return files

def ensure_release_notes(repo_name, version, conn):
    """Fetch and cache release notes + breaking changes detection."""
    ver_row = conn.execute(
        "SELECT release_notes, has_breaking_changes FROM chart_versions WHERE repo_name=? AND version=?",
        (repo_name, version)
    ).fetchone()
    if ver_row and ver_row['release_notes'] is not None:
        return ver_row['release_notes'], bool(ver_row['has_breaking_changes'])

    repo_row = conn.execute("SELECT github_repo FROM repos WHERE name=?", (repo_name,)).fetchone()
    if not repo_row:
        return '', False

    notes = fetch_github_release_notes(repo_row['github_repo'], version)
    has_breaking, breaking_summary = detect_breaking_changes(notes)

    conn.execute("""
        UPDATE chart_versions
        SET release_notes=?, has_breaking_changes=?, breaking_changes_summary=?
        WHERE repo_name=? AND version=?
    """, (notes, int(has_breaking), '\n---\n'.join(breaking_summary), repo_name, version))
    conn.commit()
    return notes, has_breaking

# ─── API Routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/repos')
def api_repos():
    db = get_db()
    rows = db.execute("SELECT * FROM repos ORDER BY name").fetchall()
    result = []
    for r in rows:
        result.append({
            'name': r['name'],
            'helm_repo_url': r['helm_repo_url'],
            'chart_name': r['chart_name'],
            'github_repo': r['github_repo'],
            'latest_version': r['latest_version'],
            'last_checked': r['last_checked'],
        })
    return jsonify(result)

@app.route('/api/repos/<repo_name>/versions')
def api_versions(repo_name):
    db = get_db()
    # Check if we have versions; if not, sync first
    count = db.execute(
        "SELECT COUNT(*) as cnt FROM chart_versions WHERE repo_name=?", (repo_name,)
    ).fetchone()['cnt']
    if count == 0:
        ok, msg = sync_repo(repo_name)
        if not ok:
            return jsonify({'error': msg}), 500

    rows = db.execute("""
        SELECT version, release_date, has_breaking_changes, breaking_changes_summary
        FROM chart_versions WHERE repo_name=?
        ORDER BY rowid DESC
    """, (repo_name,)).fetchall()

    versions = [dict(r) for r in rows]

    # Sort by semver
    def ver_key(v):
        try:
            return Version(v['version'].lstrip('v'))
        except InvalidVersion:
            return Version('0.0.0')
    versions = sorted(versions, key=ver_key, reverse=True)

    repo_row = db.execute("SELECT latest_version FROM repos WHERE name=?", (repo_name,)).fetchone()
    latest = repo_row['latest_version'] if repo_row else None

    return jsonify({'versions': versions, 'latest': latest})

@app.route('/api/repos/<repo_name>/diff')
def api_diff(repo_name):
    version_a = request.args.get('from')
    version_b = request.args.get('to')
    if not version_a or not version_b:
        return jsonify({'error': 'Provide ?from=X&to=Y'}), 400

    db = get_db()

    # Ensure chart files are cached for both versions
    files_a = ensure_chart_files_cached(repo_name, version_a, db)
    files_b = ensure_chart_files_cached(repo_name, version_b, db)

    if not files_a and not files_b:
        return jsonify({'error': 'Could not fetch chart files'}), 500

    diff = build_diff(files_a, files_b, version_a, version_b)

    # Get release notes for both
    notes_a, breaking_a = ensure_release_notes(repo_name, version_a, db)
    notes_b, breaking_b = ensure_release_notes(repo_name, version_b, db)

    # Get breaking changes from DB (all versions between a and b)
    ver_rows = db.execute("""
        SELECT version, release_notes, has_breaking_changes, breaking_changes_summary
        FROM chart_versions WHERE repo_name=?
    """, (repo_name,)).fetchall()

    all_versions_sorted = sort_versions([r['version'] for r in ver_rows])
    try:
        idx_a = all_versions_sorted.index(version_a)
        idx_b = all_versions_sorted.index(version_b)
    except ValueError:
        idx_a, idx_b = 0, 0

    # Versions between b (newer) and a (older)
    if idx_b <= idx_a:
        between = all_versions_sorted[idx_b:idx_a+1]
    else:
        between = all_versions_sorted[idx_a:idx_b+1]

    between_versions = []
    for r in ver_rows:
        if r['version'] in between:
            between_versions.append({
                'version': r['version'],
                'has_breaking_changes': bool(r['has_breaking_changes']),
                'breaking_changes_summary': r['breaking_changes_summary'] or '',
                'release_notes': r['release_notes'] or '',
            })
    between_versions.sort(key=lambda x: ver_key_fn(x['version']), reverse=True)

    total_additions = sum(f['additions'] for f in diff)
    total_deletions = sum(f['deletions'] for f in diff)
    changed_files = [f for f in diff if f['status'] != 'unchanged']

    return jsonify({
        'from_version': version_a,
        'to_version': version_b,
        'diff': diff,
        'changed_files': len(changed_files),
        'total_additions': total_additions,
        'total_deletions': total_deletions,
        'notes_from': notes_a,
        'notes_to': notes_b,
        'breaking_in_from': breaking_a,
        'breaking_in_to': breaking_b,
        'versions_between': between_versions,
    })

def ver_key_fn(v):
    try:
        return Version(v.lstrip('v'))
    except InvalidVersion:
        return Version('0.0.0')

@app.route('/api/repos/<repo_name>/release-notes/<version>')
def api_release_notes(repo_name, version):
    db = get_db()
    notes, has_breaking = ensure_release_notes(repo_name, version, db)
    ver_row = db.execute(
        "SELECT breaking_changes_summary FROM chart_versions WHERE repo_name=? AND version=?",
        (repo_name, version)
    ).fetchone()
    return jsonify({
        'version': version,
        'release_notes': notes,
        'has_breaking_changes': has_breaking,
        'breaking_changes_summary': ver_row['breaking_changes_summary'] if ver_row else '',
    })

@app.route('/api/repos/<repo_name>/sync', methods=['POST'])
def api_sync_repo(repo_name):
    ok, msg = sync_repo(repo_name)
    status = 200 if ok else 500
    return jsonify({'ok': ok, 'message': msg}), status

@app.route('/api/repos/sync-all', methods=['POST'])
def api_sync_all():
    db = get_db()
    repos = db.execute("SELECT name FROM repos").fetchall()
    results = {}
    for r in repos:
        ok, msg = sync_repo(r['name'])
        results[r['name']] = msg
    return jsonify(results)

@app.route('/api/repos', methods=['POST'])
def api_add_repo():
    data = request.json
    required = ['name', 'helm_repo_url', 'chart_name', 'github_repo']
    for f in required:
        if not data.get(f):
            return jsonify({'error': f'Missing field: {f}'}), 400
    db = get_db()
    try:
        db.execute("""
            INSERT INTO repos (name, helm_repo_url, chart_name, github_repo)
            VALUES (?, ?, ?, ?)
        """, (data['name'], data['helm_repo_url'], data['chart_name'], data['github_repo']))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Repo already exists'}), 409
    return jsonify({'ok': True})

# ─── Startup ─────────────────────────────────────────────────────────────────

def start_background_scheduler():
    t = threading.Thread(target=background_scheduler, daemon=True)
    t.start()
    logger.info("Background scheduler started (runs every 24h).")

if __name__ == '__main__':
    try:
        from packaging.version import Version, InvalidVersion
    except ImportError:
        logger.warning("packaging not installed; version sorting may be degraded.")
        class Version:
            def __init__(self, v): self.v = v
            def __lt__(self, o): return self.v < o.v
            def __gt__(self, o): return self.v > o.v
        class InvalidVersion(Exception): pass

    init_db()
    start_background_scheduler()
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
else:
    try:
        from packaging.version import Version, InvalidVersion
    except ImportError:
        class Version:
            def __init__(self, v): self.v = v
        class InvalidVersion(Exception): pass
    init_db()
    start_background_scheduler()