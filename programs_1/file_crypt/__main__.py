import argparse
import logging
import os
from pathlib import Path

import pyAesCrypt as pac

from settings import MIN_PASSWORD_LEN, BUFFER_SIZE, PASSWORD, EXTENSION
from typing import Union


class Crypt(object):

    sources = None
    is_dir = False
    is_file = False

    def __init__(self, path, password, delete=True):
        self.path = path
        self.delete = delete
        self.password = password

    def do_crypt(self, path_to_output=None) -> None:
        self._start(
            self._encrypt_file,
            path_to_output
        )

    def do_decrypt(self, path_to_output=None) -> None:
        self._start(
            self._decrypt_file,
            path_to_output
        )

    def _start(self, method, path_to_output: str = None) -> None:
        if self.is_file:
            self.sources = self.method(self.path, self.path)
        elif self.is_dir:
            self.sources = self._dirs_travel(method, self.path, self.path)

    def _dirs_travel(self, method, path: Path, path_to_output: Path) -> list:
        """
        Walk through directory and encrypts all inner file

        :param path_to_dir:
        :param path_to_output:
        :return: list of path to encrypt file
        """
        sources = []
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = Path(root) / file
                new_path = method(
                    file_path.absolute(),
                    file_path.absolute()
                )
                sources.append(new_path)
        return sources

    def _encrypt_file(self, file_path: str, path_to_output: str) -> Path:
        """
        Encrypt file with password

        :param file_path: path to the file
        :param path_to_output: path to output encrypt file
        :return: Path to output file
        """
        pac.encryptFile(file_path,
                        path_to_output.with_suffix(EXTENSION),
                        self.password,
                        BUFFER_SIZE)
        if self.delete:
            os.unlink(file_path)
        return Path(path_to_output)

    def _decrypt_file(self, file_path: str, path_to_output: str) -> Path:
        """
        Decrypt file

        :param file_path: path to the file
        :param path_to_output: path to output decrypt file
        :return: Path to output file
        """
        pac.decryptFile(file_path,
                        path_to_output.with_suffix(''),
                        self.password,
                        BUFFER_SIZE)
        return Path(path_to_output)

    def _check_path(self, path):
        if path and isinstance(path, str):
            path = Path(path)
            if any([path.is_dir(), path.is_file()]):
                return path
        raise Exception("Path is not a file or directions")

    def _check_password(self, password):
        if password and isinstance(password, (str, int)):
            password = str(password)
            if len(password) >= MIN_PASSWORD_LEN:
                return password
        raise Exception("Password is not valid, min password %s" % MIN_PASSWORD_LEN)

    def get_path(self):
        return self._path

    def set_path(self, path):
        self._path = self._check_path(path)
        self.is_dir = True if self._path.is_dir() else False
        self.is_file = True if self._path.is_file() else False

    def get_password(self):
        return self._password

    def set_password(self, password):
        self._password = self._check_password(password)

    path = property(get_path, set_path)
    password = property(get_password, set_password)


def get_args() -> tuple:
    """
    Returned parameter of terminal arguments

    :return: tuple of path, password
    """
    parser = argparse.ArgumentParser(description='File encryption and decryption service')

    parser.add_argument('--run', type=str, required=False, help='Run task from file')
    parser.add_argument('-password', type=str, required=False, help='The password for encrypt')
    parser.add_argument('-path', type=str, required=False, help='The path to the folder to be encrypted')
    parser.add_argument('-output', type=str, required=False, help='The path to save encrypt file')

    args = parser.parse_args()
    return args.path, \
           args.password if args.password is not None else PASSWORD


if __name__ == "__main__":
    path, password = get_args()
    crypt = Crypt(path, password, True)
    # crypt.do_crypt()
    crypt.do_decrypt()
