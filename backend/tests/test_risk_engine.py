"""
SENTINEL-GRC — Risk Engine Tests
Tests the FAIR calculation logic for various risk severities.
"""

from app.services.risk_engine import risk_engine

def test_fair_calculation_low_risk():
    """Test FAIR calculation for a low risk scenario"""
    calc = risk_engine.calculate_risk(
        asset_value_gbp=10_000,
        threat_event_frequency=0.1,
        vulnerability_probability=0.2,
        primary_loss_magnitude_gbp=500,
        secondary_loss_magnitude_gbp=0,
        regulatory_fine_exposure_gbp=0,
    )
    assert calc["severity"] == "low"
    assert calc["ale_mean_gbp"] > 0
    assert calc["exploitation_probability_12m"] < 0.1

def test_fair_calculation_critical_risk():
    """Test FAIR calculation for a critical risk scenario"""
    calc = risk_engine.calculate_risk(
        asset_value_gbp=5_000_000,
        threat_event_frequency=10.0,
        vulnerability_probability=0.9,
        primary_loss_magnitude_gbp=1_000_000,
        secondary_loss_magnitude_gbp=500_000,
        regulatory_fine_exposure_gbp=10_000_000,
    )
    assert calc["severity"] == "critical"
    assert calc["ale_mean_gbp"] > 1_000_000
    assert calc["exploitation_probability_12m"] > 0.5
