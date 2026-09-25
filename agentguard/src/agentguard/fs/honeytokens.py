"""
AgentGuard Workspace Honeytokens (§4.9)
"""
import os
import random
import string
from typing import List, Tuple, Dict, Any

def _generate_random_string(length: int, chars: str = string.ascii_uppercase + string.digits) -> str:
    return "".join(random.choices(chars, k=length))

def generate_honeytokens() -> Tuple[Dict[str, bytes], List[str]]:
    """
    Generates fully random honeytoken file contents and their secret canary values.
    Returns:
        (files_dict, canaries)
        where files_dict maps relative path -> (bytes content, marker string)
    """
    
    # 1. AWS Key: AKIA + 16 random [A-Z0-9]
    aws_key = "AKIA" + _generate_random_string(16)
    
    # 40-char secret (e.g. AWS secret or generic token)
    aws_secret = _generate_random_string(40, string.ascii_letters + string.digits + "/+")
    
    # 2. Database URL with 24 random characters
    db_pass = _generate_random_string(24, string.ascii_letters + string.digits)
    db_url = f"DATABASE_URL=postgres://admin:{db_pass}@db.internal.example:5432/prod"
    
    # 3. Fake GitHub token: ghp_ + 36 random alnum
    gh_token = "ghp_" + _generate_random_string(36, string.ascii_letters + string.digits)
    
    env_marker = f"HT_MARKER_ENV_{random.randint(1000, 9999)}"
    env_backup_content = (
        f"# {env_marker}\n"
        f"AWS_ACCESS_KEY_ID={aws_key}\n"
        f"AWS_SECRET_ACCESS_KEY={aws_secret}\n"
        f"{db_url}\n"
        f"GITHUB_TOKEN={gh_token}\n"
    ).encode("utf-8")
    
    prod_marker = f"HT_MARKER_PROD_{random.randint(1000, 9999)}"
    prod_creds_content = (
        "{\n"
        f'  "_marker": "{prod_marker}",\n'
        f'  "aws_access_key": "{aws_key}",\n'
        f'  "aws_secret": "{aws_secret}",\n'
        f'  "db_url": "{db_url}",\n'
        f'  "gh_token": "{gh_token}"\n'
        "}\n"
    ).encode("utf-8")
    
    files = {
        ".env.backup": (env_backup_content, env_marker),
        "config/prod_credentials.json.bak": (prod_creds_content, prod_marker)
    }
    
    canaries = [aws_key, aws_secret, db_pass, gh_token]
    
    return files, canaries

def plant_honeytokens(scratch_dir_fd: int) -> List[Dict[str, str]]:
    """
    Plants honeytokens into the scratch directory.
    Returns: planted list of {"path": str, "marker": str}
    """
    from agentguard.fs.safeio import safe_write_replace, open_no_follow
    import os
    
    files, canaries = generate_honeytokens()
    planted_honeytokens = []
    
    for rel_path, (content, marker) in files.items():
        # Ensure parent dirs exist
        dirname, _, _ = rel_path.rpartition("/")
        if dirname:
            # We must create the dir if it doesn't exist
            current_fd = os.dup(scratch_dir_fd)
            try:
                for comp in dirname.split("/"):
                    try:
                        os.mkdir(comp, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    
                    try:
                        nfd = os.open(comp, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0x00010000) | getattr(os, "O_NOFOLLOW", 0x00020000), dir_fd=current_fd)
                    except OSError:
                        # Should not happen unless symlink race
                        raise
                    
                    os.close(current_fd)
                    current_fd = nfd
            finally:
                os.close(current_fd)
                
        # Write file atomically
        import time
        safe_write_replace(scratch_dir_fd, rel_path, content, f"honey_{time.time_ns()}")
        planted_honeytokens.append({"path": rel_path, "marker": marker})
        
    return planted_honeytokens
