import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Search for .env in backend/ dir first, then project root
_config_dir = Path(__file__).resolve().parent.parent.parent  # backend/
_env_candidates = [_config_dir / ".env", _config_dir.parent / ".env"]
for _env_path in _env_candidates:
    if _env_path.exists():
        load_dotenv(_env_path)
        break
else:
    load_dotenv()  # fallback to default search

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ashen_dev.db")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey123")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Refuse to start with default secret in any non-dev context
if JWT_SECRET == "supersecretkey123":
    print("WARNING: JWT_SECRET is using the default value. Create a .env file and set a strong secret.")
    # Remove the line below if you want it to hard-fail instead of just warn
    # sys.exit(1)