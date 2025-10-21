import os
import json
import gzip
import requests
import tempfile
from typing import List, Dict, Any
from datetime import datetime
import config  # Assumes a config.py providing NVDHISTORICALDIR, USEGITHUBDATA, GITHUBRAWBASEURL

class DataProcessor:
    def __init__(self):
        self.historicaldir = config.NVDHISTORICALDIR
        self.usegithub = getattr(config, "USEGITHUBDATA", False)
        self.githubbaseurl = getattr(config, "GITHUBRAWBASEURL", None) if self.usegithub else None

    def get_last_5_years_data(self) -> Dict[str, List[Dict]]:
        current_year = datetime.now().year
        years = list(range(current_year - 4, current_year + 1))
        print(f"Historical Loading data for years: {years}")
        alldata = {}
        for year in years:
            print(f"Loading historical data for year: {year}")
            yeardata = self.load_year_file(year)
            if yeardata:
                alldata[str(year)] = yeardata
                print(f"Loaded {len(yeardata)} CVEs for year {year}")
            else:
                print(f"No historical data found for year {year}")
        return alldata

    def get_year_data(self, year: int) -> List[Dict]:
        return self.load_year_file(year)

    def fetch_from_github(self, filename: str) -> bytes:
        if not self.usegithub or not self.githubbaseurl:
            raise Exception("GitHub data fetching is not enabled")
        url = f"{self.githubbaseurl}/{filename}"
        print(f"Historical Fetching from GitHub URL: {url}")
        try:
            response = requests.get(url, timeout=60)
            if response.status_code == 200:
                print(f"Successfully fetched {filename} from GitHub, {len(response.content)} bytes")
                return response.content
            else:
                print(f"GitHub fetch failed: HTTP {response.status_code}")
                raise Exception(f"Failed to fetch from GitHub: HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"GitHub fetch error: {e}")
            raise Exception(f"GitHub fetch error: {e}")

    def load_year_file(self, year: int) -> List[Dict]:
        possible_filenames = [
            f"CVE-{year}.json.gz",
            f"nvdcve-1.1-{year}.json.gz",
            f"nvdcve-2.0-{year}.json.gz",
            f"CVE-{year}.json",
            f"nvdcve-1.1-{year}.json",
            f"nvdcve-2.0-{year}.json",
        ]
        data = None
        filename_used = None
        for filename in possible_filenames:
            try:
                fpath = os.path.join(self.historicaldir, filename)
                if os.path.exists(fpath):
                    print(f"Found file locally: {fpath}")
                    with (gzip.open(fpath, "rt", encoding="utf-8") if filename.endswith(".gz")
                          else open(fpath, "r", encoding="utf-8")) as f:
                        jdata = json.load(f)
                elif self.usegithub:
                    print(f"Trying to fetch file from GitHub: {filename}")
                    rawdata = self.fetch_from_github(filename)
                    if filename.endswith(".gz"):
                        with tempfile.NamedTemporaryFile(delete=False) as tmp:
                            tmp.write(rawdata)
                            tmp.flush()
                            with gzip.open(tmp.name, "rt", encoding="utf-8") as f:
                                jdata = json.load(f)
                        os.remove(tmp.name)
                    else:
                        jdata = json.loads(rawdata.decode("utf-8"))
                else:
                    continue

                # Determine format and extract CVEs
                if "CVE_Items" in jdata:
                    data = [self._standardize_cve_rec(cve) for cve in jdata["CVE_Items"]]
                elif "vulnerabilities" in jdata:
                    data = [self._standardize_cve_rec(cve) for cve in jdata["vulnerabilities"]]
                elif isinstance(jdata, list):
                    data = [self._standardize_cve_rec(cve) for cve in jdata]
                else:
                    data = []
                filename_used = filename
                print(f"Loaded {len(data)} CVEs from {filename_used} for year {year}")
                break  # Stop after first successful load
            except Exception as e:
                print(f"Error loading {filename} for year {year}: {e}")
                continue
        return data if data else []

    def _standardize_cve_rec(self, cvedata: Dict) -> Dict:
        try:
            cveid = cvedata.get("cve", {}).get("CVE_data_meta", {}).get("ID") or cvedata.get("id")
            description = ""
            # Try nested extraction
            if "cve" in cvedata and "description" in cvedata["cve"]:
                descs = cvedata["cve"]["description"].get("description_data", [])
                for descobj in descs:
                    if descobj.get("lang") == "en":
                        description = descobj.get("value", "")
                        break
            elif "description" in cvedata:
                description = cvedata.get("description", "")
            severity = (
                cvedata.get("impact", {})
                .get("baseMetricV3", {})
                .get("cvssV3", {})
                .get("baseSeverity")
                or cvedata.get("severity")
            )
            cwe = None
            problemtypes = []
            if "cve" in cvedata and "problemtype" in cvedata["cve"]:
                problemtypes = cvedata["cve"]["problemtype"].get("problemtype_data", [])
                for pt in problemtypes:
                    for desc in pt.get("description", []):
                        value = desc.get("value", "")
                        if value.startswith("CWE-"):
                            cwe = value
                            break
                    if cwe:
                        break
            elif "cwe" in cvedata:
                cwe = cvedata.get("cwe")
            published = (
                cvedata.get("publishedDate") or
                cvedata.get("published") or
                cvedata.get("published_at")
            )
            last_modified = (
                cvedata.get("lastModifiedDate") or
                cvedata.get("last_modified") or
                cvedata.get("modified_at")
            )
            return {
                "ID": cveid,
                "Description": description,
                "Severity": severity,
                "CWE": cwe,
                "Published": published,
                "LastModified": last_modified,
                "References": cvedata.get("references", []),
                "Products": cvedata.get("products", []),
                "CVSSScore": None,  # Add this later if needed
                "metrics": cvedata.get("metrics", {}),
            }
        except Exception as e:
            print(f"Error standardizing CVE record: {e}")
            return {}