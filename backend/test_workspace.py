import io
import os
import stat
import urllib.request
import urllib.error
from pathlib import Path

from workspace import EncryptedWorkspace

def test_workspace_initialization():
    workspace = EncryptedWorkspace()
    try:
        assert workspace.key is not None
        assert len(workspace.key) == 32
        
        path = Path(workspace.tmp_dir)
        assert path.exists()
        assert path.is_dir()
        
        # Windows doesn't fully support POSIX permissions, but we can check if we tried to set them
        # os.stat(workspace.tmp_dir).st_mode & 0o777 == 0o700 is true on unix
        if os.name == 'posix':
            mode = os.stat(workspace.tmp_dir).st_mode
            assert mode & 0o777 == stat.S_IRWXU
    finally:
        workspace.__exit__(None, None, None)

def test_write_and_read_decrypted():
    with EncryptedWorkspace() as workspace:
        data = b"secret test data"
        workspace.write_encrypted("test.txt", io.BytesIO(data))
        
        # Verify file exists on disk
        filepath = workspace.path / "test.txt"
        assert filepath.exists()
        
        # Verify it is encrypted (doesn't contain plaintext)
        raw_content = filepath.read_bytes()
        assert data not in raw_content
        
        # Verify we can read it decrypted
        decrypted = workspace.read_decrypted("test.txt")
        assert decrypted == data

def test_http_server_get():
    with EncryptedWorkspace() as workspace:
        data = b"hello world via http"
        workspace.write_encrypted("file.bin", io.BytesIO(data))
        
        url = workspace.get_url("file.bin")
        
        with urllib.request.urlopen(url) as response:
            assert response.status == 200
            result = response.read()
            assert result == data

def test_http_server_put():
    with EncryptedWorkspace() as workspace:
        url = workspace.get_url("upload.bin")
        data = b"uploaded data"
        
        req = urllib.request.Request(url, data=data, method="PUT")
        with urllib.request.urlopen(req) as response:
            assert response.status == 201
            
        filepath = workspace.path / "upload.bin"
        assert filepath.exists()
        raw_content = filepath.read_bytes()
        assert data not in raw_content
        
        decrypted = workspace.read_decrypted("upload.bin")
        assert decrypted == data

def test_workspace_cleanup():
    workspace = EncryptedWorkspace()
    tmp_dir = workspace.tmp_dir
    key = workspace.key
    
    workspace.__enter__()
    workspace.__exit__(None, None, None)
    
    assert not Path(tmp_dir).exists()
    assert workspace.key is None
    # Verify the bytearray was zeroized
    assert all(b == 0 for b in key)

def test_sha256():
    with EncryptedWorkspace() as workspace:
        data = b"test sha256"
        workspace.write_encrypted("hash.bin", io.BytesIO(data))
        
        import hashlib
        expected_hash = hashlib.sha256(data).hexdigest()
        assert workspace.sha256("hash.bin") == expected_hash
