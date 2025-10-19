import traceback
import sys
import os

# Patch api_client BEFORE any imports
original_import = __builtins__.__import__

def tracking_import(name, *args, **kwargs):
    """Track what's importing what"""
    result = original_import(name, *args, **kwargs)
    
    # Print import chain when api_client is loaded
    if 'api_client' in name:
        print(f"\n{'='*60}")
        print(f"IMPORTING: {name}")
        print(f"{'='*60}")
        for line in traceback.format_stack()[:-1]:
            print(line.strip())
        print(f"{'='*60}\n")
    
    return result

__builtins__.__import__ = tracking_import

# Now import the app
from vulnedu import app