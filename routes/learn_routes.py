from flask import Blueprint, render_template, redirect, url_for
from datetime import datetime, timezone

learn_bp = Blueprint('learn', __name__)

@learn_bp.route("/")
def learn():
    """Redirect to main learn topic"""
    return redirect(url_for('learn.learn_topic', topic='what-is-cve'))

@learn_bp.route("/<topic>")
def learn_topic(topic):
    """Learn topic pages"""
    
    CWE_TITLES = {
        "CWE-79": "Cross-Site Scripting",
        "CWE-89": "SQL Injection",
        "CWE-20": "Improper Input Validation",
        "CWE-22": "Path Traversal",
        "CWE-119": "Buffer Overflow",
        "CWE-200": "Information Exposure",
        "CWE-287": "Improper Authentication",
        "CWE-78": "OS Command Injection"
    }
    
    valid_topics = [
        'what-is-cwe', 'what-is-cve', 'cvss-scores',
        'what-is-nvd-mitre', 'cve-vs-cwe-vs-cvss'
    ]
    
    if topic not in valid_topics:
        return redirect(url_for('learn.learn_topic', topic='what-is-cve'))
    
    try:
        from services.data.api_client import api_client
        from services.analysis.cwe_processor import cwe_processor, get_vendor_risk_analysis
        
        latest_cves = api_client.get_cves_last_30_days()[:25]
        
        cwe_dict = {}
        cwe_severity = {}
        key_cwes = []
        key_cwe_titles = {}
        
        if topic == 'what-is-cwe':
            cwe_severity = cwe_processor.get_cwe_severity_data(10)
            cwe_dict = cwe_processor.get_cwe_details()
            key_cwes = cwe_processor.get_key_cwes()
            key_cwe_titles = cwe_processor.get_key_cwe_titles()
            
            try:
                vendor_risk_data = get_vendor_risk_analysis()
                
                if vendor_risk_data and 'top_10_cwes' in vendor_risk_data:
                    top_10_data = vendor_risk_data['top_10_cwes']
                    severity_matrix = vendor_risk_data.get('severity_matrix', {})
                    
                    cwe_severity = {
                        'labels': top_10_data.get('labels', []),
                        'indices': top_10_data.get('indices', []),
                        'data': {
                            'CRITICAL': [],
                            'HIGH': [],
                            'MEDIUM': [],
                            'LOW': [],
                            'UNKNOWN': []
                        }
                    }
                    
                    for cwe_code in top_10_data.get('indices', []):
                        cwe_severities = severity_matrix.get(cwe_code, {})
                        cwe_severity['data']['CRITICAL'].append(cwe_severities.get('CRITICAL', 0))
                        cwe_severity['data']['HIGH'].append(cwe_severities.get('HIGH', 0))
                        cwe_severity['data']['MEDIUM'].append(cwe_severities.get('MEDIUM', 0))
                        cwe_severity['data']['LOW'].append(cwe_severities.get('LOW', 0))
                        cwe_severity['data']['UNKNOWN'].append(cwe_severities.get('UNKNOWN', 0))
            except Exception as e:
                print(f"[Learn] Error getting vendor risk data: {e}")
                pass
        else:
            from services.analysis.severity_analyzer import get_severity_card_counts
            cwe_severity = get_severity_card_counts()
            key_cwes = list(CWE_TITLES.keys())
            key_cwe_titles = CWE_TITLES
        
        return render_template(
            f"learn/{topic}.html",
            cwe_dict=cwe_dict,
            cwe_severity=cwe_severity,
            latest_cves=latest_cves,
            key_cwes=key_cwes,
            key_cwe_titles=key_cwe_titles,
            now=datetime.now(timezone.utc)
        )
    except Exception as e:
        print(f"[Flask] Learn page error: {e}")
        
        return render_template(
            f"learn/{topic}.html",
            cwe_dict={},
            cwe_severity={},
            latest_cves=[],
            key_cwes=list(CWE_TITLES.keys()),
            key_cwe_titles=CWE_TITLES,
            now=datetime.now(timezone.utc)
        )