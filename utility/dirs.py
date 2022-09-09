from os import makedirs


def create_dirs(path):
    makedirs(path, exist_ok=True)
