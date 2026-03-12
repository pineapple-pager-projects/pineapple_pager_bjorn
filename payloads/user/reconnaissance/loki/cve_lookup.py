# cve_lookup.py
# CVE / Threat Intelligence Enrichment
# - CISA KEV (Known Exploited Vulnerabilities) catalog: bundled offline
# - NVD API: optional online lookup for CVSS scores

import os
import json
import time
import logging
from datetime import datetime
from logger import Logger

logger = Logger(name="cve_lookup.py", level=logging.INFO)

# NVD API rate limits
NVD_RATE_NO_KEY = 6.0    # seconds between requests (5 req/30s)
NVD_RATE_WITH_KEY = 0.6  # seconds between requests (50 req/30s)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_REQUEST_TIMEOUT = 15


class KevDatabase:
    """CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, kev_path):
        self._db = {}
        self._catalog_date = None
        self._loaded = False
        if kev_path and os.path.exists(kev_path):
            self._load(kev_path)

    def _load(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._catalog_date = data.get('catalogVersion', '')
            for entry in data.get('vulnerabilities', []):
                cve_id = entry.get('cveID', '')
                if cve_id:
                    self._db[cve_id] = entry
            self._loaded = True
            logger.debug(f"KEV catalog loaded: {len(self._db)} entries (version {self._catalog_date})")
        except Exception as e:
            logger.error(f"Failed to load KEV catalog: {e}")

    @property
    def loaded(self):
        return self._loaded

    @property
    def count(self):
        return len(self._db)

    def lookup(self, cve_id):
        """Look up a CVE in the KEV catalog. Returns enrichment dict or None."""
        entry = self._db.get(cve_id)
        if not entry:
            return None
        return {
            'kev': True,
            'ransomware_use': entry.get('knownRansomwareCampaignUse', 'Unknown'),
            'required_action': entry.get('requiredAction', ''),
            'vendor_project': entry.get('vendorProject', ''),
            'product': entry.get('product', ''),
            'vulnerability_name': entry.get('vulnerabilityName', ''),
            'due_date': entry.get('dueDate', ''),
        }

    def is_known_exploited(self, cve_id):
        return cve_id in self._db

    def update(self, download_url=None):
        """Download fresh KEV catalog from CISA."""
        if download_url is None:
            download_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            import urllib.request
            logger.info("Downloading fresh KEV catalog from CISA...")
            req = urllib.request.Request(download_url, headers={'User-Agent': 'Bjorn-KEV-Updater/1.0'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                new_data = json.loads(resp.read().decode('utf-8'))
            # Validate it has the expected structure
            vulns = new_data.get('vulnerabilities', [])
            if not vulns:
                logger.error("Downloaded KEV catalog has no vulnerabilities — aborting update")
                return False
            # Find the kev_catalog.json path
            kev_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'kev_catalog.json')
            os.makedirs(os.path.dirname(kev_path), exist_ok=True)
            with open(kev_path, 'w', encoding='utf-8') as f:
                json.dump(new_data, f)
            # Reload
            self._db.clear()
            self._load(kev_path)
            logger.info(f"KEV catalog updated: {len(self._db)} entries")
            return True
        except Exception as e:
            logger.error(f"Failed to update KEV catalog: {e}")
            return False


class NvdClient:
    """Optional NVD API client for CVSS score lookups."""

    def __init__(self, api_key=None, cache_path=None):
        self.api_key = api_key
        self.rate_delay = NVD_RATE_WITH_KEY if api_key else NVD_RATE_NO_KEY
        self._last_request = 0
        self._cache = {}
        self._cache_path = cache_path
        if cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    self._cache = json.load(f)
                logger.debug(f"NVD cache loaded: {len(self._cache)} entries")
            except Exception:
                self._cache = {}

    def _save_cache(self):
        if self._cache_path:
            try:
                os.makedirs(os.path.dirname(self._cache_path), exist_ok=True)
                with open(self._cache_path, 'w') as f:
                    json.dump(self._cache, f)
            except Exception as e:
                logger.warning(f"Failed to save NVD cache: {e}")

    def lookup_cve(self, cve_id):
        """Query NVD for CVSS data. Returns dict or None."""
        # Check cache first
        if cve_id in self._cache:
            return self._cache[cve_id]

        try:
            import urllib.request
            import urllib.error

            # Rate limiting
            elapsed = time.time() - self._last_request
            if elapsed < self.rate_delay:
                time.sleep(self.rate_delay - elapsed)

            url = f"{NVD_API_URL}?cveId={cve_id}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Bjorn-NVD-Client/1.0'})
            if self.api_key:
                req.add_header('apiKey', self.api_key)

            self._last_request = time.time()
            with urllib.request.urlopen(req, timeout=NVD_REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            vulns = data.get('vulnerabilities', [])
            if not vulns:
                self._cache[cve_id] = None
                self._save_cache()
                return None

            cve_data = vulns[0].get('cve', {})
            metrics = cve_data.get('metrics', {})

            # Try CVSS v3.1 first, then v3.0, then v2.0
            cvss_score = None
            cvss_severity = None
            for version_key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    cvss_severity = cvss_data.get('baseSeverity', '')
                    if not cvss_severity and cvss_score is not None:
                        # Derive severity from score
                        if cvss_score >= 9.0:
                            cvss_severity = 'CRITICAL'
                        elif cvss_score >= 7.0:
                            cvss_severity = 'HIGH'
                        elif cvss_score >= 4.0:
                            cvss_severity = 'MEDIUM'
                        else:
                            cvss_severity = 'LOW'
                    break

            # Get description
            desc_list = cve_data.get('descriptions', [])
            description = ''
            for d in desc_list:
                if d.get('lang') == 'en':
                    description = d.get('value', '')
                    break

            result = {
                'cvss_score': cvss_score,
                'cvss_severity': cvss_severity.upper() if cvss_severity else None,
                'nvd_description': description,
            }
            self._cache[cve_id] = result
            self._save_cache()
            return result

        except Exception as e:
            logger.warning(f"NVD lookup failed for {cve_id}: {e}")
            return None


# Severity ordering for sorting
_SEVERITY_ORDER = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'INFORMATIONAL': 4,
}


def _finding_sort_key(finding):
    """Sort key: KEV first, then by CVSS severity, then by risk field."""
    kev = finding.get('kev', False)
    cvss = finding.get('cvss_score')
    cvss_sev = finding.get('cvss_severity', '')
    risk = finding.get('risk', 'Informational').upper()

    # KEV findings always sort first
    kev_rank = 0 if kev else 1

    # Use CVSS severity if available, else fall back to risk field
    if cvss_sev:
        sev_rank = _SEVERITY_ORDER.get(cvss_sev.upper(), 4)
    else:
        sev_rank = _SEVERITY_ORDER.get(risk, 4)

    # Within same severity, higher CVSS score first
    cvss_rank = -(cvss if cvss is not None else 0)

    return (kev_rank, sev_rank, cvss_rank)


def enrich_findings(findings, kev_db, nvd_client=None):
    """Enrich vulnerability findings with KEV and optionally NVD data.

    Args:
        findings: list of finding dicts from _vuln_details.json
        kev_db: KevDatabase instance
        nvd_client: optional NvdClient instance

    Returns:
        Enriched findings list sorted by severity.
    """
    if not findings:
        return findings

    for finding in findings:
        cves = finding.get('cves', [])
        finding_kev = False
        finding_ransomware = 'Unknown'
        finding_required_action = ''
        finding_cvss_score = None
        finding_cvss_severity = None

        for cve_id in cves:
            # KEV lookup
            if kev_db and kev_db.loaded:
                kev_info = kev_db.lookup(cve_id)
                if kev_info:
                    finding_kev = True
                    if kev_info['ransomware_use'] == 'Known':
                        finding_ransomware = 'Known'
                    if kev_info['required_action'] and not finding_required_action:
                        finding_required_action = kev_info['required_action']

            # NVD lookup
            if nvd_client:
                nvd_info = nvd_client.lookup_cve(cve_id)
                if nvd_info and nvd_info.get('cvss_score') is not None:
                    # Keep the highest CVSS score across all CVEs in this finding
                    if finding_cvss_score is None or nvd_info['cvss_score'] > finding_cvss_score:
                        finding_cvss_score = nvd_info['cvss_score']
                        finding_cvss_severity = nvd_info['cvss_severity']

        # Add enrichment fields
        finding['kev'] = finding_kev
        finding['ransomware_use'] = finding_ransomware
        if finding_required_action:
            finding['required_action'] = finding_required_action
        if finding_cvss_score is not None:
            finding['cvss_score'] = finding_cvss_score
            finding['cvss_severity'] = finding_cvss_severity

    # Sort by severity (KEV first, then CVSS/risk)
    findings.sort(key=_finding_sort_key)

    return findings
