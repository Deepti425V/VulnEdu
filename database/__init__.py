from .db_manager import DatabaseManager
try:
    from .models import CVEDatabase, CWEDatabase
except ImportError:
    # Models might not exist yet
    CVEDatabase = None
    CWEDatabase = None

# Global database instance
db_manager = DatabaseManager()

__all__ = ['db_manager', 'DatabaseManager', 'CVEDatabase', 'CWEDatabase']