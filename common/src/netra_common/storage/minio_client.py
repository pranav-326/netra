"""MinIO / S3 Object Storage Client Wrapper."""

import io
from typing import BinaryIO, Optional
from minio import Minio
from minio.error import S3Error
import logging

logger = logging.getLogger("netra.storage.minio")


class MinioStorageClient:
    """Wrapper around Minio Python SDK providing bucket checks and safe file operations."""

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        secure: bool = False,
    ):
        self.endpoint = endpoint
        self.access_key = access_key
        self.secret_key = secret_key
        self.secure = secure
        self.client = Minio(
            endpoint=self.endpoint,
            access_key=self.access_key,
            secret_key=self.secret_key,
            secure=self.secure,
        )

    def ensure_bucket(self, bucket_name: str) -> None:
        """Create bucket if it does not already exist."""
        try:
            if not self.client.bucket_exists(bucket_name):
                self.client.make_bucket(bucket_name)
                logger.info(f"Created MinIO bucket: {bucket_name}")
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
        """Upload raw bytes to a MinIO bucket."""
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
        """Fetch raw bytes for an object from MinIO."""
        response = None
        try:
            response = self.client.get_object(bucket_name, object_name)
            return response.read()
        finally:
            if response:
                response.close()
                response.release_conn()

    def check_health(self) -> bool:
        """Health check verifying connection to MinIO service."""
        try:
            self.client.list_buckets()
            return True
        except Exception as e:
            logger.warning(f"MinIO healthcheck failed: {e}")
            return False
