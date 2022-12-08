import argparse
import os
import zipfile
from pathlib import Path
from typing import Optional, Tuple
from zipfile import ZipFile
from shutil import move
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


def _encrypt_file(file_path: Path, path_out: Path, password: str, delete: bool = True) -> Path:
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


def _decrypt_file(file_path: Path, path_to_output: Path, password: str, delete: bool = True) -> Path:
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


def _dirs_travel(method, path: Path,
                 output: Path,
                 password: str,
                 to_zip: bool = False,
                 delete: bool = True
                 ) -> list:
    """
    Walk through directory and encrypts all inner file
    """
    if path is not output:
        output.mkdir(exist_ok=True)

    # crypt all files in dir
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

    # dir in zip
    if to_zip:
        output = create_zip(path.name, sources)

    # move dir
    if delete and path is not output:
        move(path, output)

    return output


def encrypt_dir(path: str, output: str, password: str, to_zip: bool = False, delete: bool = True):
    """
    Crypt all files in dir
    """
    path = _check_path(path)
    password = _check_password(password)
    output = _check_path_out(output) if output else path

    crypt_files = _dirs_travel(
        _encrypt_file, path, output, password, to_zip, delete)
    return crypt_files


def decrypt_dir(path: str, output: str, password: str, to_zip: bool = False, delete: bool = True):
    """
    Decrypt all files in dir
    """
    path = _check_path(path)
    password = _check_password(password)
    output = _check_path_out(output) if output else path

    return _dirs_travel(
        _decrypt_file, path, output, password, to_zip, delete)


def create_zip(name: str = None, files: list = None) -> str:
    """
    Create zip archive and save to the path

    :param str name: name for zip
    :param str files: path to source
    :return: None или tuple объект, путь и название файла.
    """
    try:
        assert files, "Have not data for create zip."

        path_to_zip = Path(r'%s.zip' % name)

        new_zip = zipfile.ZipFile(path_to_zip, 'w')
        for file in files:
            new_zip.write(filename=file, arcname=file.as_posix())
        new_zip.close()
    except Exception as e:
        raise e

    return path_to_zip

def get_args() -> tuple:
    """
    Returned parameter of terminal arguments

    :return: tuple of path, password
    """
    parser = argparse.ArgumentParser(description='File encryption and decryption service')

    parser.add_argument('--run', type=str, required=False, help='Run task from file')
    parser.add_argument('-zip', type=bool, required=False, help='Zip crypt file or not')
    parser.add_argument('-password', type=str, required=False, help='The password for encrypt')
    parser.add_argument('-output', type=str, required=False, help='The path to save encrypt file')
    parser.add_argument('-path', type=str, required=False, help='The path to the folder to be encrypted')

    args = parser.parse_args()
    return args.path, \
           args.zip if args.zip else False, \
           args.output if args.output else None, \
           args.password if args.password is not None else PASSWORD


if __name__ == "__main__":
    path, zip, output, password = get_args()

    # new_file = encrypt_file(path, output, password)
    # new_output = decrypt_file(new_file, output, password)

    new_file = encrypt_dir(path, output, password, zip)
    new_file = decrypt_dir(path, output, password, zip)
