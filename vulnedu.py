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

if __name__ == '__main__':
    # This only runs in local development
    print("[Flask] Starting VulnEdu in DEVELOPMENT mode...")
    
    # Create required directories
    for directory in [config.CACHE_DIR, config.NVD_DIR, config.NVD_HISTORICAL_DIR, config.NVD_PROCESSED_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    # Run with basic settings for local dev
    app.run(host='0.0.0.0', port=5000, debug=True)
