import os 
import re

from admin import username

def where_dat(username):
    homepath = os.path.expanduser(f"~{username}")
    return homepath

def is_safe_path(username):
    # Unix username rules:
    # - Start with lowercase letter or underscore
    # - Followed by lowercase letters, digits, underscore, or hyphen
    # - Optional $ at the end
    # - Max 31 characters
    pattern = r"^[a-z_][a-z0-9_-]{0,30}$|^[a-z_][a-z0-9_-]{0,29}\$$"

    # Strict pattern (no $ at end, for builds with poor support)
    s_pattern = r"^[a-z_][a-z0-9_-]{0,30}$"

    if not re.match(s_pattern, username):
        return False

    if not re.match(pattern, username):
        return False

    return True

homepath = where_dat(username)

def where_plus(homepath, path_string):
    new_path = homepath + f"{path_string}"
    return new_path

def path_exists(new_path):
    if os.path.exists(new_path):
        print(f'Already exists: {new_path}')
        return True
    else:
        print(f'Creating... {new_path}')
        os.makedirs(new_path, exist_ok=True)
        return False