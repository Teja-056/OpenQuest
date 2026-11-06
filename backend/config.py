import os
from pathlib import Path

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"
QUARANTINE_DIR = BACKEND_DIR / "quarantine"
ML_DIR = PROJECT_ROOT / "ml"
ML_MODEL_DIR = ML_DIR / "model"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
ML_MODEL_DIR.mkdir(parents=True, exist_ok=True)

def load_dotenv():
    """Simple, zero-dependency .env loader that checks backend/.env and project root .env."""
    env_paths = [
        BACKEND_DIR / ".env",
        PROJECT_ROOT / ".env"
    ]
    for env_file in env_paths:
        if env_file.is_file():
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip().strip("'\"")
                            if key not in os.environ:
                                os.environ[key] = val
            except Exception as e:
                print(f"[Config] Warning: Failed to parse .env file at {env_file}: {e}")

# Load environment variables
load_dotenv()

class Config:
    """Application configuration for AI Shield."""
    ENV = os.environ.get("FLASK_ENV", "development")
    DEBUG = os.environ.get("FLASK_DEBUG", "1").lower() in ("1", "true", "yes")
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", 5000))
    SECRET_KEY = os.environ.get("SECRET_KEY", "ai-shield-dev-secret-key-2026")
    JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", 24))
    CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")
    PERSISTENCE_MODE = os.environ.get("PERSISTENCE_MODE", "auto").lower()  # auto, supabase, sqlite

    # Supabase PostgreSQL credentials
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
    SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()

    # Paths
    LOCAL_DB_PATH = str(DATA_DIR / "aishield_local.db")
    QUARANTINE_PATH = str(QUARANTINE_DIR)
    ML_MODEL_PATH = str(ML_MODEL_DIR / "isolation_forest.joblib")
    ML_METADATA_PATH = str(ML_MODEL_DIR / "model_metadata.json")

    # Security & Agent Guard
    AGENT_VIOLATION_THRESHOLD = int(os.environ.get("AGENT_VIOLATION_THRESHOLD", 3))
    RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", 120))  # requests per minute
    RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", 60))  # seconds

    @classmethod
    def is_supabase_configured(cls) -> bool:
        """Check whether Supabase environment variables are provided and not default placeholders."""
        if not cls.SUPABASE_URL or not cls.SUPABASE_SERVICE_ROLE_KEY:
            return False
        placeholder_indicators = [
            "your-project",
            "your-supabase",
            "your_supabase",
            "placeholder",
            "insert_here",
            "enter_here"
        ]
        key_lower = cls.SUPABASE_SERVICE_ROLE_KEY.lower()
        if any(ind in key_lower for ind in placeholder_indicators):
            return False
        return True
