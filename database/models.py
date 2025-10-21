from typing import Dict, List, Any


class CVEDatabase:
    """CVE database model"""
    
    @staticmethod
    def from_api_format(api_data: Dict) -> Dict:
        """Convert API format to database format"""
        return {
            'ID': api_data.get('ID', ''),
            'Description': api_data.get('Description', ''),
            'Severity': api_data.get('Severity', 'UNKNOWN'),
            'CVSS_Score': api_data.get('CVSS_Score'),
            'CWE': api_data.get('CWE'),
            'Published': api_data.get('Published', ''),
            'lastModified': api_data.get('lastModified', ''),
            'References': api_data.get('References', []),
            'Products': api_data.get('Products', []),
            'metrics': api_data.get('metrics', {})
        }


class CWEDatabase:
    """CWE database model (for future use)"""
    
    @staticmethod
    def from_api_format(api_data: Dict) -> Dict:
        """Convert API format to database format"""
        return {
            'code': api_data.get('code', ''),
            'name': api_data.get('name', ''),
            'description': api_data.get('description', ''),
            'mitigations': api_data.get('mitigations', []),
            'examples': api_data.get('examples', [])
        }