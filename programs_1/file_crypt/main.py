import pyAesCrypt as pac
from pathlib import Path
import argparse
import logging
from settings import MIN_PASSWORD_LEN, BUFFER_SIZE
import os


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


def dirs_travel(path_to_dir, password):
    files_struct = []
    for root, dirs, files in os.walk(path_to_dir):
        for file in files:
            file_path = Path(root) / file
            files_struct.append(
                encrypt_file(file_path.as_posix(), password)
            )
    pass


if __name__ == "__main__":
    path = Path('/home/serg/PycharmProjects/py_programs/programs_1/file_crypt/test')
    dirs_travel(path, '1234567')



