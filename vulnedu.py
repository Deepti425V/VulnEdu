from flask import Flask
from routes.main_routes import main_bp
from routes.api_routes import api_bp
from routes.learn_routes import learn_bp
from routes.utility_routes import utility_bp
import config
import os

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.SECRET_KEY
    
    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(learn_bp, url_prefix='/learn')
    app.register_blueprint(utility_bp)
    
    # Health check endpoint for Render
    @app.route('/health')
    def health():
        return {'status': 'healthy', 'service': 'VulnEdu'}, 200
    
    return app

# Create the app instance at module level for Gunicorn
app = create_app()

# Initialize the app with the file caching system
try:
    from app_startup import initialize_app
    print("[Flask] Initializing app with file cache system...")
    initialize_app(use_file_cache=True)
    print("[Flask] File cache initialization complete")
except Exception as e:
    print(f"[Flask] Error initializing file cache system: {e}")
    import traceback
    traceback.print_exc()

if __name__ == "__main__":
    # This only runs in local development
    print("[Flask] Starting VulnEdu in DEVELOPMENT mode...")
    
    # Create required directories
    for directory in [config.CACHE_DIR, config.NVD_DIR, config.NVD_HISTORICAL_DIR, config.NVD_PROCESSED_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    # Create file cache directory if it doesn't exist yet
    file_cache_dir = "./data/file_cache"
    if not os.path.exists(file_cache_dir):
        os.makedirs(file_cache_dir, exist_ok=True)
        print(f"[Flask] Created file cache directory: {file_cache_dir}")
    
    # Check if cache files exist and suggest generating them if not
    cache_files = [f for f in os.listdir(file_cache_dir) if f.endswith('.json.gz')]
    if not cache_files:
        print("[Flask] WARNING: No cache files found in data/file_cache directory")
        print("[Flask] For better performance, generate cache files with:")
        print("[Flask] python generate_cache.py --years 3")
    else:
        print(f"[Flask] Found {len(cache_files)} cache files in data/file_cache")
    
    # Run with basic settings for local dev
    app.run(host='0.0.0.0', port=5000, debug=True)