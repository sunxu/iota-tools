"""Register the independent R2 upload and download addons."""
from tah_control.config import load_settings
from r2_client.download import R2DownloadRouter
from r2_client.upload import R2UploadRouter

_settings = load_settings()
addons = [
    R2UploadRouter(_settings),
    R2DownloadRouter(_settings),
]
