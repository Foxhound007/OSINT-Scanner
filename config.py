from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
BASE_DOMAIN = "gcb.bank"
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
