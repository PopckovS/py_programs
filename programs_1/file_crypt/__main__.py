import argparse
import logging
import os
from pathlib import Path

import pyAesCrypt as pac

from settings import MIN_PASSWORD_LEN, BUFFER_SIZE, PASSWORD, EXTENSION
from typing import Union


def encrypt_file(
        file_path: Union[Path, str],
        password: str,
        extension: str,
        ignor_error: bool = True) -> Path:
    """
    Encrypt file with password

    :param file_path: path to the file
    :param password: password for encrypt file
    :param extension: file extension for encrypt
    :param ignor_error: ignor error or not
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

    new_path = file_path.as_posix().with_suffix(extension)
    pac.encryptFile(file_path,
                    new_path,
                    password,
                    BUFFER_SIZE)
    return Path(new_path)


def decrypt_file(file_path: Union[Path, str], password: str) -> Path:
    """
     Decrypt file with password

    :param file_path:
    :param password:
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

    new_path = file_path.as_posix().with_suffix(extension)
    pac.decryptFile(file_path,
                    new_path,
                    password,
                    BUFFER_SIZE)
    return Path(new_path)


def dirs_travel_encrypt(path_to_dir: Union[Path, str], password: str) -> list:
    """
    Walk through directory and encrypts all inner file

    :param path_to_dir:
    :param password:
    :return: list of path to encrypt file
    """
    files_struct = []
    for root, dirs, files in os.walk(path_to_dir):
        for file in files:
            file_path = Path(root) / file
            files_struct.append(
                encrypt_file(file_path.as_posix(), password)
            )
    pass


def get_args() -> argparse:
    """
    Returned parameter of terminal arguments

    :return: argparse object
    """
    parser = argparse.ArgumentParser(description='File encryption and decryption service')

    parser.add_argument('-ex', type=str, required=False, help='Extension for encrypt file')
    parser.add_argument('-password', type=str, required=False, help='The password for encrypt')
    parser.add_argument('-path', type=str, required=False, help='The path to the folder to be encrypted')
    return parser.parse_args()


if __name__ == "__main__":
    _args = get_args()

    if _args.path:
        path = Path(_args.path)
        extension = _args.ex if hasattr(_args, "ex") else EXTENSION
        password = _args.password if hasattr(_args, "password") else PASSWORD

        if path.is_dir():
            dirs_travel_encrypt(
                path.as_posix(), password, extension)

        if path.is_file():
            encrypt_file(
                path.as_posix(), password, extension)
