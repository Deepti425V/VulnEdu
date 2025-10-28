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
    app = Flask(__name__, static_folder="static", template_folder="templates")
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

    # ------------------------------------------------------------------------------
    # ⚠️ IMPORTANT FIX:
    # Disable heavy preloading of all historical CVE data when running on Render
    # or when SKIP_PRELOAD=true is set in the environment.
    # This makes startup instant and avoids Render timeouts.
    # ------------------------------------------------------------------------------

    skip_preload = os.getenv("SKIP_PRELOAD", "false").lower() == "true"

    if not config.running_on_render() and not skip_preload:
        try:
            from services.data.data_processor import historical_loader
            years = historical_loader.get_available_years()
            print(f"[Startup] Found {len(years)} years: {years}")
            # Only preload the most recent year (fast startup)
            if years:
                latest = max(years)
                print(f"[Startup] Preloading latest year only: {latest}")
                historical_loader.get_year_data(latest)
            print("[Startup] Preloaded one-year cache successfully")
        except Exception as e:
            print(f"[Startup] Aggregator note: {e}")
    else:
        print("[Startup] Skipping heavy historical preload on Render or SKIP_PRELOAD=true")

    # Launch dev server
    app.run(host="0.0.0.0", port=5000, debug=True)
