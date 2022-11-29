import argparse
import os
from pathlib import Path

import pyAesCrypt as pac

from settings import MIN_PASSWORD_LEN, BUFFER_SIZE, PASSWORD, CRYPT_EXTENSION


def _check_path(path: str) -> Path:
    if path and isinstance(path, (Path, str)):
        path = Path(path)
        if any([path.is_dir(), path.is_file()]):
            return path
    raise Exception("Path is not a file or directions")


def _check_password(password: str) -> Path:
    if password and isinstance(password, (str, int)):
        password = str(password)
        if len(password) >= MIN_PASSWORD_LEN:
            return password
    raise Exception("Password is not valid, min password %s" % MIN_PASSWORD_LEN)


def _check_path_out(output: str):
    if isinstance(output, (Path, str)):
        return Path(output)
    raise Exception('Path `%s` is not a str for output file' % output.absolute())


def encrypt_file(path: str, path_out: str, password: str, delete: bool = True):
    path = _check_path(path)
    password = _check_password(password)
    path_out = _check_path_out(path_out) if path_out else path

    return _encrypt_file(
        path, path_out, password, delete)


def decrypt_file(path: str, path_out: str, password: str, delete: bool = True):
    path = _check_path(path)
    password = _check_password(password)
    path_out = _check_path_out(path_out) if path_out else path

    return _decrypt_file(
        path, path_out, password, delete)


def _encrypt_file(file_path: Path,
                  path_out: Path,
                  password: str,
                  delete: bool = True
                  ) -> Path:
    """
    Encrypt file with password
    """
    new_file = path_out.with_suffix(path_out.suffix + CRYPT_EXTENSION)
    pac.encryptFile(file_path.absolute(),
                    new_file.absolute(),
                    password,
                    BUFFER_SIZE)
    if delete:
        file_path.unlink()
    return new_file


def _decrypt_file(file_path: Path,
                  path_to_output: Path,
                  password: str,
                  delete: bool = True
                  ) -> Path:
    """
    Decrypt file
    """
    new_file = path_to_output.with_suffix('')
    pac.decryptFile(file_path.absolute(),
                    new_file,
                    password,
                    BUFFER_SIZE)
    if delete:
        file_path.unlink()
    return new_file


def _dirs_travel(method,
                 path: Path,
                 output: Path,
                 password: str,
                 delete: bool = True
                 ) -> list:
    """
    Walk through directory and encrypts all inner file
    """
    if path is not output:
        output.mkdir(exist_ok=True)

    sources = []
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = Path(root) / file
            file_outpath = Path(root) / file
            new_path = method(file_path.absolute(),
                              file_outpath.absolute(),
                              password,
                              delete
                              )
            sources.append(new_path)
    if delete and path is not output:
        path.unlink()
    return sources


def encrypt_dir(path: str, output: str, password: str, delete: bool = True):
    path = _check_path(path)
    password = _check_password(password)
    output = _check_path_out(output) if output else path

    return _dirs_travel(
        _encrypt_file, path, output, password, delete)


def decrypt_dir(path: str, output: str, password: str, delete: bool = True):
    path = _check_path(path)
    password = _check_password(password)
    output = _check_path_out(output) if output else path

    return _dirs_travel(
        _decrypt_file, path, output, password, delete)


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
           args.output if args.output else None, \
           args.password if args.password is not None else PASSWORD


if __name__ == "__main__":
    path, output, password = get_args()

    # new_file = encrypt_file(path, output, password)
    # new_output = decrypt_file(new_file, output, password)

    new_file = encrypt_dir(path, output, password)
    new_file = decrypt_dir(path, output, password)
