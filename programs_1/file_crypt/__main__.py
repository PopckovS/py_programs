import argparse
import logging
import os
from pathlib import Path

import pyAesCrypt as pac

from settings import MIN_PASSWORD_LEN, BUFFER_SIZE, PASSWORD


def encrypt_file(file_path: Path, password: str, ignor_error=True):
    """
    Encrypt file

    :param file_path:
    :param password:
    :param ignor_error:
    :return:
    """

    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        logging.error("Password not not valid or too short. Min password %s", MIN_PASSWORD_LEN)
        return

    if not isinstance(file_path, (Path, str)):
        logging.error("File path not valid")
        return

    if not isinstance(file_path, Path):
        file_path = Path(file_path)

    new_path = file_path.as_posix().with_suffix('.aes')

    pac.encryptFile(file_path,
                    new_path,
                    password,
                    BUFFER_SIZE
                    )
    return Path(new_path)


def decrypt_file():
    pass


def dirs_travel_encrypt(path_to_dir, password):
    files_struct = []
    for root, dirs, files in os.walk(path_to_dir):
        for file in files:
            file_path = Path(root) / file
            files_struct.append(
                encrypt_file(file_path.as_posix(), password)
            )
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='File encryption and decryption service')

    parser.add_argument('--path', type=str, required=False, help='The path to the folder to be encrypted')
    parser.add_argument('--password', type=str, required=False, help='The password for encrypt')
    _args = parser.parse_args()

    if _args.path:
        path = Path(_args.path)

        if path.is_dir():
            dirs_travel_encrypt(
                path.as_posix(),
                _args.password if hasattr(_args, "password") else PASSWORD
            )

        if path.is_file():
            encrypt_file(
                path.as_posix(),
                _args.password if hasattr(_args, "password") else PASSWORD
            )




