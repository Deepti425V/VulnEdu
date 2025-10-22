from flask import Blueprint, jsonify, request
from services.orchestrator import data_orchestrator

api_bp = Blueprint('api', __name__)

@api_bp.route('/cve/<cve_id>')
def api_cve_detail(cve_id):
    """API endpoint for CVE details"""
    try:
        cve = data_orchestrator.get_cve_detail(cve_id)
        return jsonify({'success': True, 'data': cve})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/clear-cache', methods=['POST'])
def clear_cache():
    """API endpoint to clear cache"""
    try:
        data_orchestrator.clear_cache()
        return jsonify({'success': True, 'message': 'Cache cleared'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/warm-cache', methods=['POST', 'GET'])
def warm_cache():
    """Manually warm cache with full data - HIT THIS BEFORE YOUR PRESENTATION!"""
    try:
        print("[API] ===== MANUAL CACHE WARMING TRIGGERED =====")
        result = data_orchestrator.warm_cache_full()
        return jsonify(result)
    except Exception as e:
        print(f"[API] Error warming cache: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/force-refresh')
def force_refresh():
    """Force refresh API data"""
    try:
        print("[API] Forcing data refresh...")
        data_orchestrator.clear_cache()
        
        from services.analysis.severity_analyzer import get_severity_card_counts
        severity_counts = get_severity_card_counts()
        
        return jsonify({
            'success': True,
            'counts': severity_counts,
            'message': f"Refreshed with {severity_counts['total_cves']} CVEs"
        })
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@api_bp.route('/data-source-status')
def data_source_status():
    """API endpoint to check current data source configuration"""
    try:
        status = data_orchestrator.get_data_source_status()
        return jsonify({'success': True, 'data': status})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/timeline-data')
def get_timeline_data():
    """API endpoint for dynamic timeline loading - LOADS HISTORICAL DATA"""
    try:
        years = request.args.get('years', default=1, type=int)
        if years not in [1, 2, 3, 5]:
            years = 1
        
        print(f"[API] Loading timeline data for {years} years from historical files")
        
        from services.analysis.trend_analyzer import get_vulnerabilities_over_time_last_n_years
        timeline_data = get_vulnerabilities_over_time_last_n_years(years)
        
        return jsonify({
            'success': True,
            'timeline': timeline_data,
            'years': years
        })
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@api_bp.route('/cwe/<cwe_code>')
def api_cwe_detail(cwe_code):
    """API endpoint for CWE details"""
    try:
        cwe_details = {
            'CWE-79': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.',
                'mitigations': [
                    'Use output encoding/escaping for all untrusted data',
                    'Implement Content Security Policy (CSP)',
                    'Validate and sanitize all input on server side'
                ],
                'examples': [
                    '<script>alert(XSS)</script> in user input field',
                    'URL parameter injection: ?search=<script>stealCookies()</script>'
                ],
                'relationships': [('CWE-20', 'ChildOf'), ('CWE-80', 'ParentOf'), ('CWE-81', 'ParentOf')],
                'source': 'scraped'
            },
            'CWE-89': {
                'name': 'SQL Injection',
                'description': 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component.',
                'mitigations': [
                    'Use parameterized queries/prepared statements',
                    'Implement input validation and sanitization',
                    'Apply principle of least privilege for database accounts'
                ],
                'examples': [
                    "' OR '1'='1 in login form",
                    "'; DROP TABLE users--"
                ],
                'relationships': [('CWE-74', 'ChildOf'), ('CWE-943', 'ParentOf')],
                'source': 'scraped'
            }
        }
        
        cwe_info = cwe_details.get(cwe_code, {
            'name': f'CWE {cwe_code}',
            'description': f'Detailed information for {cwe_code} would be fetched from MITRE database.',
            'mitigations': ['Contact security team for specific mitigation strategies'],
            'examples': ['Examples would be loaded from MITRE database'],
            'relationships': [],
            'source': 'placeholder'
        })
        
        return jsonify({'success': True, 'data': cwe_info})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/test-api-connection')
def test_api_connection():
    """Test API connection and return basic stats"""
    try:
        from services.data.api_client import api_client
        from datetime import datetime
        
        cache_stats = api_client.get_cache_stats()
        
        test_results = {
            'api_key_configured': bool(api_client.api_key),
            'cache_stats': cache_stats,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'message': 'API connection test successful',
            'data': test_results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/cache-stats')
def cache_stats():
    """Get cache statistics"""
    try:
        stats = data_orchestrator.get_cache_stats()
        return jsonify({'success': True, 'data': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/health')
def health_check():
    """Simple health check endpoint"""
    from datetime import datetime
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'VulnEdu API'
    })
