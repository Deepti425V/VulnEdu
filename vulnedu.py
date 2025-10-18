from flask import Flask
from routes.main_routes import main_bp
from routes.api_routes import api_bp
from routes.learn_routes import learn_bp
from routes.utility_routes import utility_bp
from services.data.data_source_config import data_source_config
import config

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.SECRET_KEY
    
    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(learn_bp, url_prefix='/learn')
    app.register_blueprint(utility_bp)
    
    return app

# Create the app instance at module level for Gunicorn
app = create_app()

if __name__ == "__main__":
    print("[Flask] Starting VulnEdu application...")
    print(f"[Flask] Data directory: {config.DATA_DIR}")
    print(f"[Flask] Cache directory: {config.CACHE_DIR}")
    print(f"[Flask] API Key configured: {'YES' if config.NVD_API_KEY else 'NO'}")
    
    # Create required directories
    import os
    for directory in [config.CACHE_DIR, config.NVD_DIR, config.NVD_HISTORICAL_DIR, config.NVD_PROCESSED_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    # Log data source configuration
    print("\n=== Data Source Configuration ===")
    data_source_config.log_data_source_status()
    print("==================================\n")
    
    # Clear cache on startup and warm up
    try:
        from services.cache.cache_manager import cache_manager
        cache_manager.clear_cache()
        print("[Flask] Cache cleared on startup")
        
        # Warm up cache with background loading
        cache_manager.warm_up_cache()
        print("[Flask] Cache warm-up initiated")
    except Exception as e:
        print(f"[Flask] Error with cache operations: {e}")
    
    app.run(host='0.0.0.0', port=5000, debug=True)