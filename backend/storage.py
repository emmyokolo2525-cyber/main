import os
from pathlib import Path

def get_storage_dir() -> Path:
    storage_dir = Path(os.getenv("HARPOCRATES_STORAGE_DIR", "/tmp/harpocrates_jobs"))
    storage_dir.mkdir(parents=True, exist_ok=True)
    return storage_dir

def get_job_input_path(job_id: int | str) -> Path:
    return get_storage_dir() / f"job_{job_id}_input"

def get_job_output_path(job_id: int | str) -> Path:
    return get_storage_dir() / f"job_{job_id}_output"
