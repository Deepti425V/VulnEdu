from flask import Blueprint, jsonify, request
from services.orchestrator import data_orchestrator
import threading

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
    """Start staged cache warming in background"""
    try:
        print("[API] ===== STAGED CACHE WARMING TRIGGERED =====")
        
        thread = threading.Thread(target=data_orchestrator.warm_cache_staged)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Staged cache warming started in background (10-15 minutes)',
            'check_progress_at': '/api/loading-progress'
        })
    except Exception as e:
        print(f"[API] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/loading-progress', methods=['GET'])
def loading_progress():
    """Check loading progress - REFRESH THIS TO TRACK PROGRESS"""
    try:
        progress = data_orchestrator.get_loading_progress()
        return jsonify({
            'success': True,
            'progress': progress
        })
    except Exception as e:
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
