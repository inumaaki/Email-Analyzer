import os
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

# Threat Intelligence APIs
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

# Config
SANDBOX_DIR = os.getenv("SANDBOX_DIR", "./analysis/output/")
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", 50))
