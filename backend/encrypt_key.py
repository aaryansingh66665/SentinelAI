import os
import sys

# Add root folder to sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

# Load .env file if present (for local development)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(root_dir, ".env"))
except ImportError:
    pass  # dotenv not installed; fall back to environment variables

from tools.security import encrypt_data

# Read the API key from the environment — never hardcode secrets here.
# Set GEMINI_API_KEY in your .env file (see .env.example) or as a system
# environment variable before running this script.
API_KEY = os.environ.get("GEMINI_API_KEY", "")
PASSPHRASE = os.environ.get("ENCRYPT_PASSPHRASE", "sentinel")  # Default decryption passphrase

if __name__ == "__main__":
    if not API_KEY:
        print("ERROR: GEMINI_API_KEY environment variable is not set.")
        print("Create a .env file based on .env.example and set your key there.")
        sys.exit(1)

    encrypted = encrypt_data(API_KEY, PASSPHRASE)
    env_enc_path = os.path.join(root_dir, ".env.enc")
    with open(env_enc_path, "w") as f:
        f.write(encrypted)
    print(f"Successfully encrypted and saved Gemini API Key to {env_enc_path} using passphrase '{PASSPHRASE}'.")

