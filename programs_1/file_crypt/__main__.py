import argparse
import logging
import os
from pathlib import Path

import pyAesCrypt as pac

from settings import MIN_PASSWORD_LEN, BUFFER_SIZE, PASSWORD, EXTENSION
from typing import Union


def encrypt_file(file_path: Union[Path, str],
                 password: str,
                 ex: str) -> Path:
    """
    Encrypt file with password

    :param file_path: path to the file
    :param password: password for encrypt file
    :param ex: file extension for encrypt
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

    new_path = file_path.as_posix().with_suffix(ex)
    pac.encryptFile(file_path,
                    new_path,
                    password,
                    BUFFER_SIZE)
    return Path(new_path)


def decrypt_file(file_path: Union[Path, str],
                 password: str,
                 ex: str) -> Path:
    """
     Decrypt file with password

    :param file_path:
    :param password:
    :param ex:
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

    new_path = file_path.as_posix().with_suffix(ex)
    pac.decryptFile(file_path,
                    new_path,
                    password,
                    BUFFER_SIZE)
    return Path(new_path)


# TODO path_to_output
def dirs_travel_encrypt(path_to_dir: Union[Path, str],
                        path_to_output: Union[Path, str],
                        password: str
                        ) -> list:
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


def get_args() -> tuple:
    """
    Returned parameter of terminal arguments

    :return: tuple of path, password, extension
    """
    parser = argparse.ArgumentParser(description='File encryption and decryption service')

    parser.add_argument('-ex', type=str, required=False, help='Extension for encrypt file')
    parser.add_argument('-password', type=str, required=False, help='The password for encrypt')
    parser.add_argument('-path', type=str, required=False, help='The path to the folder to be encrypted')

    args = parser.parse_args()
    return args.path, \
           args.password if args.password is not None else PASSWORD, \
           args.ex if args.ex is not None else EXTENSION


def args_validate(path: Path, password: str, ex: str) -> tuple:
    if path:
        path = Path(path)
        if not any([path.is_dir(), path.is_file()]):
            logging.error('Path is not a file or directions')
            raise Exception

    if not password:
        logging.error('Please use password')
        raise Exception

    # TODO ex validate

    return path, password, ex


def start(path, password, ex):

    if path.is_dir():
        dirs_travel_encrypt(
            path.as_posix(), password, ex)

    if path.is_file():
        encrypt_file(
            path.as_posix(), password, ex)


if __name__ == "__main__":
    args = get_args()
    args = args_validate(*args)
    start(*args)
