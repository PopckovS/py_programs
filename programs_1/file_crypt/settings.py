from os import environ
from dotenv import load_dotenv

load_dotenv()

"""min password length"""
MIN_PASSWORD_LEN = int(environ.get("MIN_PASSWORD_LEN", 5))
"""buffer size"""
BUFFER_SIZE = environ.get("BUFFER_SIZE", (512 * 1024))
"""password for encrypt"""
PASSWORD = environ.get("PASSWORD", None)
"""extension for encrypt file"""
EXTENSION = environ.get("EXTENSION", '.aes')
