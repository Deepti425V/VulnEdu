from .db_manager import DatabaseManager
from .models import CVEDatabase, CWEDatabase

# Global database instance
db_manager = DatabaseManager()

__all__ = ['db_manager', 'DatabaseManager', 'CVEDatabase', 'CWEDatabase']