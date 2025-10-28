
try:
    # Import compatibility patches
    import compat
    print("[Patch] Successfully loaded compatibility layer")
except Exception as e:
    print(f"[Patch] Error loading compatibility layer: {e}")