import re

JWT_REGEX = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"

def extract_jwt_from_text(text):
    matches = re.findall(JWT_REGEX, text)
    return matches[0] if matches else None

def extract_from_file(path):
    try:
        with open(path, "r") as f:
            content = f.read()
        return extract_jwt_from_text(content)
    except FileNotFoundError:
        return None
    
def extract_all_jwts_from_file(file_path):
    """
    Extracts all JWTs from a file. JWTs are identified as three base64url strings separated by dots.
    """
    jwt_pattern = re.compile(
        r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    )
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            matches = jwt_pattern.findall(content)
            return matches if matches else []
    except FileNotFoundError:
        return []
