import os
import shutil
import subprocess
import pytest
import sys

# Add eval/fixtures to path to import make_demo_repo
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "eval", "fixtures")))
try:
    from make_demo_repo import make_demo_repo, hash_tree
except ImportError:
    make_demo_repo = None
    hash_tree = None

@pytest.fixture(scope="function")
def temp_fixture_dir(tmp_path):
    d = os.path.join(tmp_path, "demo_repo")
    yield d

def test_make_demo_repo_deterministic(temp_fixture_dir):
    # Run once
    make_demo_repo(temp_fixture_dir)
    hash1 = hash_tree(temp_fixture_dir)
    
    # Run twice
    make_demo_repo(temp_fixture_dir)
    hash2 = hash_tree(temp_fixture_dir)
    
    assert hash1 == hash2

def test_make_demo_repo_tests(temp_fixture_dir):
    make_demo_repo(temp_fixture_dir)
    
    # 1. pytest fails in the fresh fixture
    # We must use sys.executable to run pytest in a subprocess
    result_fail = subprocess.run([sys.executable, "-m", "pytest", "tests/"], cwd=temp_fixture_dir, capture_output=True)
    assert result_fail.returncode != 0
    
    # 2. programmatically apply the one-line fix
    utils_path = os.path.join(temp_fixture_dir, "src", "utils.py")
    with open(utils_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Apply fix: return re.sub(...) -> return re.sub(...).strip("-")
    content = content.replace('return re.sub(r"[^a-z0-9]+", "-", text)', 'return re.sub(r"[^a-z0-9]+", "-", text).strip("-")')
    
    with open(utils_path, "w", encoding="utf-8") as f:
        f.write(content)
        
    # 3. pytest passes after the fix
    result_pass = subprocess.run([sys.executable, "-m", "pytest", "tests/"], cwd=temp_fixture_dir, capture_output=True)
    assert result_pass.returncode == 0
