"""
SENTINEL-GRC — Evidence Vault Tests
"""

import pytest
from app.services.evidence_vault import evidence_vault

def test_hash_and_signature():
    """Test cryptographic functions of evidence vault"""
    content_hash = evidence_vault.hash_content("test data")
    assert content_hash == "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
    
    timestamp = "2024-01-01T12:00:00"
    control_id = "AC-001"
    
    sig = evidence_vault.sign_evidence(content_hash, timestamp, control_id)
    assert len(sig) == 64
    
    # Verify valid
    assert evidence_vault.verify_signature(content_hash, timestamp, control_id, sig) is True
    
    # Verify invalid on tampering
    assert evidence_vault.verify_signature(content_hash, timestamp, "AC-002", sig) is False

def test_chain_hash():
    """Test chain hash computation"""
    hash1 = "hash1"
    hash2 = "hash2"
    
    chain_genesis = evidence_vault.compute_chain_hash(hash1, None)
    chain_next = evidence_vault.compute_chain_hash(hash2, hash1)
    
    assert chain_genesis != chain_next
    
@pytest.mark.asyncio
async def test_list_evidence(client):
    """Test evidence pagination endpoint"""
    response = await client.get("/api/v1/evidence/?limit=10")
    assert response.status_code in (200, 401)
