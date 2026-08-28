from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / 'backend' / 'data'
SAMPLES_DIR = DATA_DIR / 'samples'
MODELS_DIR = BASE_DIR / 'backend' / 'models' / 'weights'

class SystemConfig(BaseModel):
    default_chunk_size: int = 1000
    flow_idle_timeout_sec: float = 30.0
    flow_active_timeout_sec: float = 120.0
    max_active_flows: int = 100_000
    log_level: str = 'INFO'
    strict_passive_mode: bool = True

config = SystemConfig()
