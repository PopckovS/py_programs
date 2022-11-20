from os import environ

# min password length
MIN_PASSWORD_LEN = environ.get("MIN_PASSWORD_LEN", 5)

# buffer size
BUFFER_SIZE = environ.get("BUFFER_SIZE", 512 * 1024)

