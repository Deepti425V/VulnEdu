# vulnedu.py — streamlined Flask entrypoint for VulnEdu
import os
from flask import Flask
from routes.main_routes import main_bp
from routes.api_routes import api_bp
from routes.learn_routes import learn_bp
from routes.utility_routes import utility_bp
import config

# --------------------------------------------------------------------------------------
# APP FACTORY
# --------------------------------------------------------------------------------------
def create_app():
    """Factory pattern for VulnEdu Flask app"""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY

    # Register blueprints
    app.register_blueprint(main_bp)                     # "/"  -> main dashboard
    app.register_blueprint(api_bp, url_prefix="/api")   # API endpoints
    app.register_blueprint(learn_bp, url_prefix="/learn")
    app.register_blueprint(utility_bp)                  # utilities, misc routes

    # Health check endpoint for Render
    @app.route("/health")
    def health():
        return {"status": "healthy", "service": "VulnEdu"}, 200

    return app


# --------------------------------------------------------------------------------------
# LOCAL DEV STARTUP
# --------------------------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    print("[Flask] Starting VulnEdu in DEVELOPMENT mode…")

    # Ensure required directories exist
    for directory in [
        config.CACHE_DIR,
        config.NVD_DIR,
        config.NVD_HISTORICAL_DIR,
        config.NVD_PROCESSED_DIR,
    ]:
        os.makedirs(directory, exist_ok=True)

    # Optional: precompute aggregates (skipped on Render)
    try:
        from services.data.data_processor import historical_loader
        years = historical_loader.get_available_years()
        print(f"[Startup] Found {len(years)} years: {years}")
        for y in years:
            historical_loader.get_year_data(y)
        print("[Startup] Preloaded one-year cache successfully")
    except Exception as e:
        print(f"[Startup] Aggregator note: {e}")

    # Launch dev server
    app.run(host="0.0.0.0", port=5000, debug=True)
