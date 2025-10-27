# startup.py
import os
import sys
from vulnedu import app

if __name__ == "__main__":
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 10000))
    print(f"Starting VulnEdu on port {port}")
    
    # Run app
    app.run(host='0.0.0.0', port=port)
```

Save this as startup.py in your project root.

Then update your Render Start Command to:
```
gunicorn --workers=1 --threads=2 --timeout=120 --bind 0.0.0.0:$PORT startup:app