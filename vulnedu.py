from flask import Flask
from routes.main_routes import main_bp
from routes.api_routes import api_bp
from routes.learn_routes import learn_bp
from routes.utility_routes import utility_bp
import config
import os
import sys

# Import memory monitor
try:
    from memory_monitor import memory_monitor
except ImportError:
    print("[Warning] memory_monitor not found, memory tracking disabled")
    memory_monitor = None

def create_app():
    """Application factory pattern - OPTIMIZED FOR RENDER FREE TIER"""
    
    print("=" * 70)
    print("🚀 STARTING VULNEDU - MEMORY OPTIMIZED MODE")
    print("=" * 70)
    
    # Log initial memory
    if memory_monitor:
        memory_monitor.log_memory("App startup")
    
    # Check if on Render
    is_render = os.environ.get('RENDER') == 'true'
    if is_render:
        print("✓ Running on Render")
        print(f"✓ Max memory limit: {config.MAX_MEMORY_MB}MB")
        print(f"✓ Max CVEs in memory: {config.MAX_CVES_IN_MEMORY}")
    else:
        print("✓ Running locally")
    
    # Verify database is available on Render
    if is_render and not os.environ.get('DATABASE_URL'):
        print("=" * 70)
        print("🔴 CRITICAL ERROR: No DATABASE_URL on Render!")
        print("=" * 70)
        print("Database is REQUIRED on Render free tier to prevent memory crashes.")
        print("Please set DATABASE_URL in Render environment variables.")
        print("=" * 70)
        sys.exit(1)
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.SECRET_KEY
    
    # Register blueprints
    print("✓ Registering blueprints...")
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(learn_bp, url_prefix='/learn')
    app.register_blueprint(utility_bp)
    
    # Health check endpoint with memory stats
    @app.route('/health')
    def health():
        """Health check with memory monitoring"""
        from database import db_manager
        
        health_status = {
            'status': 'healthy',
            'service': 'VulnEdu',
            'environment': 'render' if is_render else 'local',
            'database': 'connected' if db_manager.use_database else 'not configured'
        }
        
        # Add memory stats
        if memory_monitor:
            memory_stats = memory_monitor.get_stats()
            health_status['memory'] = memory_stats
            
            # Check if memory is critical
            if memory_stats['percent_used'] > 90:
                health_status['status'] = 'critical_memory'
                health_status['warning'] = 'Memory usage critical'
        
        # Add database stats if available
        if db_manager.use_database:
            try:
                stats = db_manager.get_stats()
                health_status['database_stats'] = stats
            except Exception as e:
                health_status['database_error'] = str(e)
        
        return health_status, 200
    
    # Memory stats endpoint (for debugging)
    @app.route('/api/memory-stats')
    def memory_stats():
        """Get current memory statistics"""
        if not memory_monitor:
            return {'error': 'Memory monitor not available'}, 500
        
        return memory_monitor.get_stats(), 200
    
    # Force garbage collection endpoint (for emergency cleanup)
    @app.route('/api/gc', methods=['POST'])
    def force_gc():
        """Force garbage collection to free memory"""
        if not memory_monitor:
            return {'error': 'Memory monitor not available'}, 500
        
        print("[API] Manual garbage collection requested")
        freed_mb = memory_monitor.force_garbage_collection()
        
        return {
            'success': True,
            'freed_mb': round(freed_mb, 2),
            'current_stats': memory_monitor.get_stats()
        }, 200
    
    print("=" * 70)
    print("✓ App initialization complete")
    
    # Final memory check
    if memory_monitor:
        memory_monitor.log_memory("App ready")
    
    print("=" * 70)
    
    return app

# Create the app instance at module level for Gunicorn
app = create_app()

if __name__ == "__main__":
    # This only runs in local development
    print("")
    print("=" * 70)
    print("🔧 DEVELOPMENT MODE")
    print("=" * 70)
    
    # Create required directories
    for directory in [config.CACHE_DIR, config.NVD_DIR, config.NVD_HISTORICAL_DIR, config.NVD_PROCESSED_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    # Check database configuration
    from database import db_manager
    if db_manager.use_database:
        print("✓ Database integration ENABLED")
        print(f"✓ Connection pool ready")
    else:
        print("⚠️ Database NOT configured - using in-memory storage")
        print("⚠️ Set DATABASE_URL environment variable to enable database")
    
    print("=" * 70)
    print("")
    
    # Run with basic settings for local dev
    app.run(host='0.0.0.0', port=5000, debug=True)