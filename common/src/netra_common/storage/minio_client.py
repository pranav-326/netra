"""S3-compatible object storage client for evidence (Layer 8).

Uses the MinIO Python SDK, a maintained general-purpose S3 client, against any
S3-compatible server. Netra runs SeaweedFS.
"""

import io
import logging

from minio import Minio
from minio.error import S3Error

logger = logging.getLogger("netra.storage")


class MinioStorageClient:
    """Bucket checks and safe object operations over the S3 API."""

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        secure: bool = False,
    ):
        if not (access_key and secret_key):
            # An empty key pair would send unsigned requests: refuse rather than guess.
            raise RuntimeError("S3_ACCESS_KEY and S3_SECRET_KEY must be set to reach the evidence store.")
        self.endpoint = endpoint
        self.secure = secure
        self.client = Minio(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure,
        )

    def ensure_bucket(self, bucket_name: str) -> None:
        """Create bucket if it does not already exist."""
        try:
            if not self.client.bucket_exists(bucket_name):
                self.client.make_bucket(bucket_name)
                logger.info(f"Created bucket: {bucket_name}")
        except S3Error as e:
            logger.error(f"Failed ensuring bucket {bucket_name}: {e}")
            raise

    def put_bytes(
        self,
        bucket_name: str,
        object_name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        """Upload raw bytes to a bucket."""
        self.ensure_bucket(bucket_name)
        stream = io.BytesIO(data)
        self.client.put_object(
            bucket_name=bucket_name,
            object_name=object_name,
            data=stream,
            length=len(data),
            content_type=content_type,
        )
        return object_name

    def get_bytes(self, bucket_name: str, object_name: str) -> bytes:
        """Fetch raw bytes for an object."""
        response = None
        try:
            response = self.client.get_object(bucket_name, object_name)
            return response.read()
        finally:
            if response:
                response.close()
                response.release_conn()

    def check_health(self) -> bool:
        """Verify the object store answers an authenticated request."""
        try:
            self.client.list_buckets()
            return True
        except Exception as e:
            logger.warning(f"Object store healthcheck failed: {e}")
            return False
