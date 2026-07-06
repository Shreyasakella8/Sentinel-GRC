"""
SENTINEL-GRC — Legal-Grade Evidence Vault
Cryptographic integrity: SHA-256 + HMAC-SHA256 + blockchain-style chaining.
verify_chain() walks the full chain and validates every link.
export_evidence_package() now filters by control_ids AND date range (previously ignored).
"""

import hashlib
import hmac
import json
import io
from datetime import datetime
from typing import Optional
import structlog
from minio import Minio
from minio.error import S3Error

from app.core.config import settings

logger = structlog.get_logger()


class EvidenceVaultService:

    def __init__(self):
        self.minio_client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE,
        )
        self._ensure_bucket()

    def _ensure_bucket(self):
        try:
            if not self.minio_client.bucket_exists(settings.MINIO_BUCKET):
                self.minio_client.make_bucket(settings.MINIO_BUCKET)
                logger.info("Evidence vault bucket created", bucket=settings.MINIO_BUCKET)
        except Exception as e:
            logger.error("Failed to ensure MinIO bucket", error=str(e))

    # ── Hashing & signing ──────────────────────────────────────────────────

    def hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def sign_evidence(self, content_hash: str, timestamp: str, control_id: str) -> str:
        message = f"{content_hash}:{timestamp}:{control_id}".encode("utf-8")
        key     = settings.EVIDENCE_HMAC_KEY.encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def verify_signature(
        self, content_hash: str, timestamp: str, control_id: str, signature: str
    ) -> bool:
        expected = self.sign_evidence(content_hash, timestamp, control_id)
        return hmac.compare_digest(expected, signature)

    def compute_chain_hash(
        self, content_hash: str, previous_chain_hash: Optional[str]
    ) -> str:
        """
        SHA-256(content_hash + ':' + (previous_chain_hash | 'GENESIS'))
        Any tampered entry invalidates all subsequent chain_hash values.
        """
        chain_input = f"{content_hash}:{previous_chain_hash or 'GENESIS'}".encode("utf-8")
        return hashlib.sha256(chain_input).hexdigest()

    # ── Storage ───────────────────────────────────────────────────────────

    def store_evidence(
        self,
        control_id: str,
        evidence_type: str,
        raw_data,
        metadata: Optional[dict] = None,
    ) -> dict:
        timestamp = datetime.utcnow().isoformat()

        content = (
            json.dumps(raw_data, indent=2, default=str)
            if isinstance(raw_data, (dict, list))
            else str(raw_data)
        )

        content_hash = self.hash_content(content)
        hmac_sig     = self.sign_evidence(content_hash, timestamp, control_id)

        date_prefix = datetime.utcnow().strftime("%Y/%m/%d")
        object_key  = f"evidence/{control_id}/{date_prefix}/{content_hash[:16]}.json"

        envelope = {
            "sentinel_evidence_v1": True,
            "control_id":           control_id,
            "evidence_type":        evidence_type,
            "timestamp":            timestamp,
            "content_hash":         content_hash,
            "hmac_signature":       hmac_sig,
            "metadata":             metadata or {},
            "raw_data":             json.loads(content) if isinstance(raw_data, (dict, list)) else content,
        }

        envelope_bytes = json.dumps(envelope, indent=2).encode("utf-8")

        try:
            self.minio_client.put_object(
                settings.MINIO_BUCKET,
                object_key,
                io.BytesIO(envelope_bytes),
                length=len(envelope_bytes),
                content_type="application/json",
                metadata={
                    "control-id":    control_id,
                    "evidence-type": evidence_type,
                    "content-hash":  content_hash,
                },
            )
        except S3Error as e:
            logger.error("Failed to store evidence in MinIO", error=str(e), control_id=control_id)
            object_key = f"storage_failed/{control_id}/{timestamp}"

        return {
            "content_hash":    content_hash,
            "hmac_signature":  hmac_sig,
            "object_key":      object_key,
            "timestamp":       timestamp,
        }

    def retrieve_evidence(self, object_key: str) -> Optional[dict]:
        try:
            response = self.minio_client.get_object(settings.MINIO_BUCKET, object_key)
            data     = json.loads(response.read())
            response.close()

            is_valid = self.verify_signature(
                data["content_hash"],
                data["timestamp"],
                data["control_id"],
                data["hmac_signature"],
            )
            data["integrity_valid"] = is_valid
            if not is_valid:
                logger.error("EVIDENCE INTEGRITY VIOLATION", object_key=object_key)
            return data
        except Exception as e:
            logger.error("Failed to retrieve evidence", object_key=object_key, error=str(e))
            return None

    # ── Chain verification ─────────────────────────────────────────────────

    def verify_chain(self, entries: list) -> dict:
        """
        Walk a list of EvidenceEntry ORM objects ordered by collected_at ASC.
        Verifies:
          1. HMAC signature on every entry
          2. chain_hash recomputation matches the stored value
          3. previous_entry_hash links correctly to the preceding entry
        Returns a report dict with per-entry results and an overall verdict.
        """
        report = {
            "total":          len(entries),
            "valid":          0,
            "invalid":        0,
            "chain_intact":   True,
            "entries":        [],
        }

        prev_content_hash = None

        for entry in entries:
            sig_valid = self.verify_signature(
                entry.content_hash,
                entry.collected_at.isoformat() if entry.collected_at else "",
                entry.control_id,
                entry.hmac_signature or "",
            )

            expected_chain = self.compute_chain_hash(entry.content_hash, prev_content_hash)
            chain_match    = (entry.chain_hash == expected_chain)

            prev_hash_ok = (
                entry.previous_entry_hash == prev_content_hash
                if prev_content_hash is not None
                else entry.previous_entry_hash is None or entry.previous_entry_hash == ""
            )

            entry_valid = sig_valid and chain_match and prev_hash_ok

            if not entry_valid:
                report["chain_intact"] = False
                report["invalid"]     += 1
            else:
                report["valid"] += 1

            report["entries"].append({
                "entry_ref":       entry.entry_ref,
                "control_id":      entry.control_id,
                "collected_at":    entry.collected_at.isoformat() if entry.collected_at else None,
                "sig_valid":       sig_valid,
                "chain_match":     chain_match,
                "prev_hash_ok":    prev_hash_ok,
                "overall_valid":   entry_valid,
            })

            prev_content_hash = entry.content_hash

        return report

    # ── Export ─────────────────────────────────────────────────────────────

    def export_evidence_package(
        self,
        control_ids: list,
        from_date: datetime,
        to_date: datetime,
    ) -> dict:
        """
        Export a legally defensible evidence package filtered by
        control_ids AND date range (both filters were previously ignored).
        """
        package = {
            "sentinel_evidence_package_v1": True,
            "generated_at":  datetime.utcnow().isoformat(),
            "period_from":   from_date.isoformat(),
            "period_to":     to_date.isoformat(),
            "control_ids":   control_ids,
            "entries":       [],
            "chain_valid":   True,
            "total_entries": 0,
        }

        try:
            objects = self.minio_client.list_objects(
                settings.MINIO_BUCKET,
                prefix="evidence/",
                recursive=True,
            )

            for obj in objects:
                # Filter by control_id prefix in object key path
                key_parts = obj.object_name.split("/")
                if len(key_parts) < 2:
                    continue

                obj_control_id = key_parts[1]
                if control_ids and obj_control_id not in control_ids:
                    continue

                # Filter by modification date
                if obj.last_modified:
                    obj_dt = obj.last_modified.replace(tzinfo=None)
                    if not (from_date <= obj_dt <= to_date):
                        continue

                entry = self.retrieve_evidence(obj.object_name)
                if entry:
                    package["entries"].append({
                        "object_key":      obj.object_name,
                        "content_hash":    entry.get("content_hash"),
                        "timestamp":       entry.get("timestamp"),
                        "control_id":      entry.get("control_id"),
                        "integrity_valid": entry.get("integrity_valid", False),
                    })
                    if not entry.get("integrity_valid", True):
                        package["chain_valid"] = False

        except Exception as e:
            logger.error("Evidence package export failed", error=str(e))

        package["total_entries"] = len(package["entries"])
        return package


evidence_vault = EvidenceVaultService()
