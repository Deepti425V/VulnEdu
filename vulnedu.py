from flask import Flask, jsonify
from routes.main_routes import main_bp
from routes.api_routes import api_bp
from routes.learn_routes import learn_bp
from routes.utility_routes import utility_bp
import config
import os
import psutil
import gc
import sys

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.SECRET_KEY or os.environ.get('SECRET_KEY', 'vulnedu-secret-key-for-dev')
    
    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(learn_bp, url_prefix='/learn')
    app.register_blueprint(utility_bp)
    
    # Health check endpoint for Render
    @app.route('/health')
    def health():
        return {'status': 'healthy', 'service': 'VulnEdu'}, 200
    
    # Memory diagnostics endpoint for Render
    @app.route('/diagnostics/memory')
    def memory_diagnostics():
        try:
            memory = psutil.virtual_memory()
            process = psutil.Process(os.getpid())
            process_memory = process.memory_info()
            
            # Force garbage collection to get accurate readings
            gc.collect()
            
            return jsonify({
                'system': {
                    'total_mb': memory.total / (1024 * 1024),
                    'available_mb': memory.available / (1024 * 1024),
                    'used_mb': memory.used / (1024 * 1024),
                    'percent_used': memory.percent
                },
                'process': {
                    'rss_mb': process_memory.rss / (1024 * 1024),
                    'vms_mb': process_memory.vms / (1024 * 1024)
                },
                'python': {
                    'version': sys.version
                }
            }), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # Database diagnostics endpoint for Render
    @app.route('/diagnostics/database')
    def database_diagnostics():
        try:
            from database.db_manager import db_manager
            db_stats = db_manager.get_stats()
            return jsonify(db_stats), 200
        except Exception as e:
            return jsonify({'error': str(e), 'database_status': 'error'}), 500
    
    return app

# Create the app instance at module level for Gunicorn
app = create_app()

if __name__ == "__main__":
    # This only runs in local development
    print("[Flask] Starting VulnEdu in DEVELOPMENT mode...")
    
    # Create required directories
    for directory in [config.CACHE_DIR, config.NVD_DIR, config.NVD_HISTORICAL_DIR,
                    config.NVD_PROCESSED_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    # Run with basic settings for local dev
    app.run(host='0.0.0.0', port=5000, debug=True)