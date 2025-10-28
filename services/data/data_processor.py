# services/data/data_processor.py
# Memory-safe historical loader for NVD yearly JSONs (NVD 2.0 + 1.1) using ijson streaming.
# - Prefers local feeds if config.USE_LOCAL_FEEDS is True (avoids DB 1000-row ceilings on Render free tier).
# - Falls back to DB only when local feeds are disabled (or not present) and DB is enabled.
# - Keeps only ONE year's data in RAM at a time; evicts older year to stay within 512 MB.

import os
import json
import gzip
import gc
from typing import List, Dict, Any, Optional
from datetime import datetime

import config
from database.db_manager import db_manager

# Third-party streaming JSON parser (tiny memory footprint)
# Ensure 'ijson' is in requirements.txt
import ijson


class HistoricalDataProcessor:
    """
    Loads historical CVEs year-by-year in a memory-safe way.
    Strategy:
      - If config.USE_LOCAL_FEEDS == True and local file exists -> STREAM FROM FILE (preferred).
      - Else if db_manager.use_database == True                 -> read from DB.
      - Else                                                     -> empty list.
    We keep only ONE year's parsed data in RAM (evict previous) to fit Render free tier memory.
    """

    def __init__(self, historical_dir: Optional[str] = None):
        self.historical_dir = historical_dir or config.NVD_HISTORICAL_DIR
        # Only keep ONE year's worth of parsed CVEs in RAM
        self._year_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._max_cache_size = 1
        self._years_available = set()
        print(f"[Historical] DataProcessor initialized")
        print(f"[Historical] Local directory: {self.historical_dir}")
        self._check_available_files()

    # --------- file discovery helpers ----------
    def _check_available_files(self):
        """Find available historical files (for local/dev)."""
        self._years_available.clear()
        if not os.path.exists(self.historical_dir):
            print(f"[Historical] Directory does not exist: {self.historical_dir}")
            try:
                os.makedirs(self.historical_dir, exist_ok=True)
            except Exception:
                pass
            return

        files = os.listdir(self.historical_dir)
        cve_files = [f for f in files if f.startswith(("CVE-", "nvdcve-"))]
        if cve_files:
            print(f"[Historical] Found {len(cve_files)} files: {cve_files}")
        for file in cve_files:
            year = None
            if file.startswith("CVE-") and "." in file:
                year_str = file[4:file.find(".")]
                if year_str.isdigit() and len(year_str) == 4:
                    year = int(year_str)
            elif file.startswith("nvdcve-") and "-" in file:
                parts = file.split("-")
                # nvdcve-1.1-YYYY.json or nvdcve-2.0-YYYY.json
                if len(parts) >= 3 and parts[2].isdigit() and len(parts[2]) == 4:
                    year = int(parts[2])
            if year and 2000 <= year <= 2050:
                self._years_available.add(year)

        if self._years_available:
            print(f"[Historical] Available years: {sorted(self._years_available)}")
        else:
            print(f"[Historical] WARNING: No files found in {self.historical_dir}")

    def get_available_years(self) -> List[int]:
        """Return the list of available local years (for local/dev)."""
        if not self._years_available:
            self._check_available_files()
        return sorted(self._years_available, reverse=True)

    # --------- main data access ----------
    def get_year_data(self, year: int) -> List[Dict[str, Any]]:
        """
        Get CVEs for a specific year.
        Priority:
          1) If local feeds enabled and file exists → stream from file (preferred to avoid DB limits).
          2) Else if DB enabled → pull from DB.
          3) Else → [].
        """
        year_str = str(year)

        # Serve from in-memory cache if present
        if year_str in self._year_cache:
            print(f"[Historical] Using cached data for {year}")
            return self._year_cache[year_str]

        # 1) Prefer local feeds if enabled and file exists
        if config.USE_LOCAL_FEEDS and self._year_file_path(year) is not None:
            data = self._stream_year_file(year)
            # Optionally mirror to DB (ONLY if you really want; this can take time/memory):
            if db_manager.use_database and data:
                try:
                    print(f"[Historical] (Optional) Saving {len(data)} CVEs for {year} to database")
                    db_manager.save_cves_batch(data)
                except Exception as e:
                    print(f"[Historical] Warning: failed to save {year} to DB: {e}")

            # keep just one year in memory
            self._evict_if_needed()
            self._year_cache[year_str] = data
            return data

        # 2) Fall back to DB if local feeds disabled/missing
        if db_manager.use_database:
            cves = db_manager.get_cves_by_filter(year=year_str)
            if cves:
                print(f"[Historical] Retrieved {len(cves)} CVEs for {year} from database")
                self._evict_if_needed()
                self._year_cache[year_str] = cves
                return cves
            else:
                print(f"[Historical] No DB rows for {year}")

        # 3) Nothing available
        print(f"[Historical] No data for {year} (local feeds disabled or file missing; DB empty)")
        return []

    # ---------- local file parsing (STREAMING, supports .json or .json.gz, NVD 2.0 + 1.1) ----------
    def _year_file_path(self, year: int) -> Optional[str]:
        patterns = [
            f"CVE-{year}.json",
            f"nvdcve-1.1-{year}.json",
            f"nvdcve-2.0-{year}.json",
            f"CVE-{year}.json.gz",
            f"nvdcve-1.1-{year}.json.gz",
            f"nvdcve-2.0-{year}.json.gz",
        ]
        for name in patterns:
            candidate = os.path.join(self.historical_dir, name)
            if os.path.exists(candidate):
                return candidate
        return None

    def _stream_year_file(self, year: int) -> List[Dict[str, Any]]:
        """
        Stream a year file from historical_dir (JSON or GZ) in a memory-safe way.
        Supports:
          - NVD 2.0: top-level "vulnerabilities": [{ "cve": {...} }, ...]
          - NVD 1.1: top-level "CVE_Items": [ {...}, ... ]
        Returns a list of normalized CVEs for that year. (Yes, it still creates a list,
        but without ever loading the full JSON into memory first.)
        """
        path = self._year_file_path(year)
        if not path:
            print(f"[Historical] No historical file found for {year}")
            return []

        total = 0
        out: List[Dict[str, Any]] = []

        # First try NVD 2.0 shape (vulnerabilities.item)
        try:
            with gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb") as f:
                for item in ijson.items(f, "vulnerabilities.item"):
                    # Each item is expected to be {"cve": {...}}
                    cve_obj = item.get("cve")
                    if not cve_obj:
                        continue
                    processed = self._process_cve_item_2_0(cve_obj)
                    if processed:
                        out.append(processed)
                        total += 1
                        if total % 10000 == 0:
                            print(f"[Historical] {year}: streamed {total} CVEs (2.0)")
            if total > 0:
                print(f"[Historical] Loaded {total} CVEs from {os.path.basename(path)} (NVD 2.0)")
                return out
        except Exception as e:
            # If parsing as 2.0 fails, fall back to 1.1
            print(f"[Historical] Note: {os.path.basename(path)} not 2.0 or parse error ({e}); trying 1.1...")

        # Fallback: NVD 1.1 shape (CVE_Items.item)
        total = 0
        out = []
        try:
            with gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb") as f:
                for cve_item in ijson.items(f, "CVE_Items.item"):
                    processed = self._process_cve_item_1_1(cve_item)
                    if processed:
                        out.append(processed)
                        total += 1
                        if total % 10000 == 0:
                            print(f"[Historical] {year}: streamed {total} CVEs (1.1)")
            print(f"[Historical] Loaded {total} CVEs from {os.path.basename(path)} (NVD 1.1)")
            return out
        except Exception as e:
            print(f"[Historical] ERROR: failed to stream {os.path.basename(path)} as 1.1: {e}")
            return []

    def _evict_if_needed(self):
        """Keep only one year's data in RAM."""
        if len(self._year_cache) >= self._max_cache_size:
            oldest = next(iter(self._year_cache.keys()))
            print(f"[Historical] Evicting {oldest} from cache to save memory")
            try:
                del self._year_cache[oldest]
            except Exception:
                pass
            gc.collect()

    # ---------- normalize NVD 2.0 CVE into your app schema ----------
    def _process_cve_item_2_0(self, cve: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            cve_id = cve.get("id")
            if not cve_id:
                return None

            # Description
            description = ""
            descs = cve.get("descriptions", [])
            if isinstance(descs, list) and descs:
                description = descs[0].get("value") or ""

            # Severity / CVSS
            severity = "UNKNOWN"
            cvss_score = None
            metrics = cve.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key)
                if isinstance(arr, list) and arr:
                    data = arr[0].get("cvssData", {})
                    cvss_score = data.get("baseScore")
                    sev = data.get("baseSeverity") or arr[0].get("baseSeverity")
                    if isinstance(sev, str):
                        severity = sev.upper()
                    break

            # CWE (collect list)
            cwe = "Unknown"
            cwe_list = []
            weaknesses = cve.get("weaknesses") or []
            for w in weaknesses:
                for d in w.get("description", []):
                    val = d.get("value")
                    if val and val.startswith("CWE-"):
                        cwe_list.append(val)
            if cwe_list:
                cwe = cwe_list[0]

            # Dates
            published = cve.get("published") or ""
            last_modified = cve.get("lastModified") or ""

            published_str = ""
            if published:
                try:
                    dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    published_str = dt.strftime("%Y-%m-%d")
                except Exception:
                    published_str = str(published).split("T")[0]

            # References
            refs = []
            references = cve.get("references", [])
            for r in references:
                url = r.get("url") or r.get("refsource")
                if url:
                    refs.append(url)

            return {
                "ID": cve_id,
                "Description": description or "No description available",
                "Severity": severity,
                "CVSS_Score": cvss_score,
                "CWE": cwe,
                "cwe_id": cwe_list,
                "Published": published_str,
                "published_date": published_str,  # YYYY-MM-DD
                "lastModified": last_modified or "",
                "References": refs,
                "Products": [],
                "metrics": {},
            }
        except Exception as e:
            print(f"[Historical] Error processing CVE (2.0): {e}")
            return None

    # ---------- normalize NVD 1.1 CVE into your app schema ----------
    def _process_cve_item_1_1(self, cve_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            cve_meta = cve_item.get("cve", {}).get("CVE_data_meta", {})
            cve_id = cve_meta.get("ID")
            if not cve_id:
                return None

            # Description
            description = ""
            descs = cve_item.get("cve", {}).get("description", {}).get("description_data", [])
            if isinstance(descs, list) and descs:
                description = descs[0].get("value") or ""

            # Severity / CVSS
            severity = "UNKNOWN"
            cvss_score = None
            impact = cve_item.get("impact", {})
            # v3 first
            v3 = impact.get("baseMetricV3", {})
            v3cvss = v3.get("cvssV3", {})
            if v3cvss:
                cvss_score = v3cvss.get("baseScore")
                sev = v3cvss.get("baseSeverity")
                if isinstance(sev, str):
                    severity = sev.upper()
            else:
                # fall back to v2
                v2 = impact.get("baseMetricV2", {})
                sev2 = v2.get("severity")
                if isinstance(sev2, str):
                    severity = sev2.upper()
                # v2 sometimes also has score
                if v2.get("cvssV2"):
                    cvss_score = v2.get("cvssV2", {}).get("baseScore")

            # CWE
            cwe = "Unknown"
            cwe_list = []
            problemtype = cve_item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
            if isinstance(problemtype, list) and problemtype:
                for entry in problemtype:
                    for d in entry.get("description", []):
                        val = d.get("value")
                        if val and val.startswith("CWE-"):
                            cwe_list.append(val)
            if cwe_list:
                cwe = cwe_list[0]

            # Dates
            published = cve_item.get("publishedDate") or ""
            last_modified = cve_item.get("lastModifiedDate") or ""

            published_str = ""
            if published:
                try:
                    dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    published_str = dt.strftime("%Y-%m-%d")
                except Exception:
                    published_str = str(published).split("T")[0]

            # References
            refs = []
            refs_data = cve_item.get("cve", {}).get("references", {}).get("reference_data", [])
            for r in refs_data:
                url = r.get("url") or r.get("refsource")
                if url:
                    refs.append(url)

            return {
                "ID": cve_id,
                "Description": description or "No description available",
                "Severity": severity,
                "CVSS_Score": cvss_score,
                "CWE": cwe,
                "cwe_id": cwe_list,
                "Published": published_str,
                "published_date": published_str,  # YYYY-MM-DD
                "lastModified": last_modified or "",
                "References": refs,
                "Products": [],
                "metrics": {},
            }
        except Exception as e:
            print(f"[Historical] Error processing CVE (1.1): {e}")
            return None


# Global instance used by analyzers/orchestrator
historical_loader = HistoricalDataProcessor()
