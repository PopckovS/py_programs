from os import environ

# min password length
MIN_PASSWORD_LEN = int(environ.get("MIN_PASSWORD_LEN", 5))

# buffer size
BUFFER_SIZE = int(environ.get("BUFFER_SIZE", 512 * 1024))

# password for encrypt
PASSWORD = str(environ.get("PASSWORD", None))

