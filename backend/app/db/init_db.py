"""
SENTINEL-GRC — Database Initialisation
Creates all tables, TimescaleDB hypertables, and seeds initial data.
Run once on first startup.
"""

import asyncio
from datetime import datetime
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.core.config import settings
from app.core.security import get_password_hash, UserRole
from app.db.database import Base

logger = structlog.get_logger()


async def create_timescale_hypertables(session: AsyncSession):
    """Convert time-series tables to TimescaleDB hypertables."""
    hypertables = [
        ("risk_scores", "recorded_at"),
        ("control_results", "executed_at"),
        ("threat_events", "detected_at"),
        ("audit_logs", "created_at"),
        ("ai_guardrail_logs", "scanned_at"),
    ]
    for table, time_col in hypertables:
        try:
            await session.execute(text(
                f"SELECT create_hypertable('{table}', '{time_col}', "
                f"if_not_exists => TRUE, migrate_data => TRUE);"
            ))
            await session.commit()
            logger.info(f"TimescaleDB hypertable created/verified", table=table)
        except Exception as e:
            await session.rollback()
            logger.warning(f"Hypertable creation skipped (may exist)", table=table, error=str(e))


async def create_performance_indexes(session: AsyncSession):
    """
    Create composite indexes for the three hottest query paths.

    Without these indexes, every control sweep and risk recalculation
    runs full table scans that scale linearly with data volume.

    Index strategy:
      - evidence_entries: frequently queried by (control_id) sorted DESC by collected_at
        → turns O(n) scan into O(log n) seek, critical for chain-hash lookups in _store_result
      - risk_scores: frequently queried by (risk_id) sorted DESC by recorded_at
        → speeds up trend chart loading in /risks/{id} endpoint
      - control_results: frequently queried by (control_id) sorted DESC by executed_at
        → speeds up DISTINCT ON window in controls list + history endpoint

    All are CREATE INDEX IF NOT EXISTS — safe to re-run on every startup.
    """
    indexes = [
        # Turns control_sweep.py L88-93 (previously unindexed scan) into an index seek
        (
            "idx_evidence_control_collected",
            "CREATE INDEX IF NOT EXISTS idx_evidence_control_collected "
            "ON evidence_entries(control_id, collected_at DESC);"
        ),
        # Speeds up /risks/{id} score history query
        (
            "idx_risk_scores_risk_recorded",
            "CREATE INDEX IF NOT EXISTS idx_risk_scores_risk_recorded "
            "ON risk_scores(risk_id, recorded_at DESC);"
        ),
        # Speeds up controls list DISTINCT ON window + history endpoint
        (
            "idx_control_results_control_executed",
            "CREATE INDEX IF NOT EXISTS idx_control_results_control_executed "
            "ON control_results(control_id, executed_at DESC);"
        ),
        # Covers risk_recalculation WHERE status IN ('open','under_treatment') full scan
        (
            "idx_risks_status",
            "CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status) "
            "WHERE status IN ('open', 'under_treatment');"
        ),
        # Speeds up threat_intelligence SELECT by external_id (unique but no partial index)
        (
            "idx_threat_events_external_id",
            "CREATE INDEX IF NOT EXISTS idx_threat_events_external_id "
            "ON threat_events(external_id);"
        ),
    ]
    for idx_name, ddl in indexes:
        try:
            await session.execute(text(ddl))
            await session.commit()
            logger.info("Performance index created/verified", index=idx_name)
        except Exception as e:
            await session.rollback()
            logger.warning("Index creation skipped", index=idx_name, error=str(e))


async def seed_frameworks(session: AsyncSession):
    """Seed compliance framework definitions."""
    from app.models.compliance import ComplianceFramework
    from sqlalchemy import select

    frameworks = [
        {
            "code": "ISO27001",
            "name": "ISO/IEC 27001:2022",
            "description": "International standard for information security management systems",
            "version": "2022",
            "mandatory_sectors": ["government", "finance", "healthcare"],
        },
        {
            "code": "NIST_CSF",
            "name": "NIST Cybersecurity Framework 2.0",
            "description": "NIST framework for improving critical infrastructure cybersecurity",
            "version": "2.0",
            "mandatory_sectors": ["us_federal", "critical_infrastructure"],
        },
        {
            "code": "SOC2",
            "name": "SOC 2 Type II",
            "description": "AICPA Trust Services Criteria for service organisations",
            "version": "2017",
            "mandatory_sectors": ["saas", "cloud_services"],
        },
        {
            "code": "CYBER_ESSENTIALS",
            "name": "Cyber Essentials Plus",
            "description": "UK government-backed certification scheme",
            "version": "2023",
            "mandatory_sectors": ["uk_government_suppliers"],
        },
        {
            "code": "UK_GDPR",
            "name": "UK GDPR",
            "description": "UK General Data Protection Regulation",
            "version": "2021",
            "mandatory_sectors": ["all_uk_organisations"],
        },
    ]

    for fw_data in frameworks:
        result = await session.execute(
            select(ComplianceFramework).where(ComplianceFramework.code == fw_data["code"])
        )
        if not result.scalar_one_or_none():
            fw = ComplianceFramework(**fw_data)
            session.add(fw)

    await session.commit()
    logger.info("Compliance frameworks seeded")


async def seed_control_catalog(session: AsyncSession):
    """Seed the control catalog with ISO 27001 / NIST / SOC2 controls."""
    from app.models.compliance import ControlCatalog
    from sqlalchemy import select

    controls = [
        # Access Control
        {
            "control_id": "AC-001",
            "name": "Password Policy Enforcement",
            "description": "Verify password policy enforces minimum length, complexity, and rotation",
            "category": "access_control",
            "runner_module": "app.control_runners.access_control.check_password_policy",
            "iso27001_clause": "A.9.4.3",
            "nist_csf": "PR.AC-1",
            "soc2_criteria": "CC6.1",
            "cyber_essentials": "CE-AC-1",
            "severity": "high",
            "frequency_hours": 24,
            "fine_exposure_gbp": 17500000,
        },
        {
            "control_id": "AC-002",
            "name": "Privileged Account Inactivity",
            "description": "Detect admin/privileged accounts unused for 90+ days",
            "category": "access_control",
            "runner_module": "app.control_runners.access_control.check_privileged_accounts",
            "iso27001_clause": "A.9.2.5",
            "nist_csf": "PR.AC-4",
            "soc2_criteria": "CC6.3",
            "cyber_essentials": "CE-AC-2",
            "severity": "critical",
            "frequency_hours": 6,
            "fine_exposure_gbp": 17500000,
        },
        {
            "control_id": "AC-003",
            "name": "Multi-Factor Authentication",
            "description": "Verify MFA is enabled for all privileged and remote access accounts",
            "category": "access_control",
            "runner_module": "app.control_runners.access_control.check_mfa",
            "iso27001_clause": "A.9.4.2",
            "nist_csf": "PR.AC-7",
            "soc2_criteria": "CC6.1",
            "cyber_essentials": "CE-AC-3",
            "severity": "critical",
            "frequency_hours": 6,
            "fine_exposure_gbp": 17500000,
        },
        # Network Security
        {
            "control_id": "NS-001",
            "name": "Database Port Exposure",
            "description": "Verify database ports (3306, 5432, 1433, 27017) are not exposed to internet",
            "category": "network_security",
            "runner_module": "app.control_runners.network.check_exposed_ports",
            "iso27001_clause": "A.13.1.1",
            "nist_csf": "PR.AC-5",
            "soc2_criteria": "CC6.6",
            "cyber_essentials": "CE-NS-1",
            "severity": "critical",
            "frequency_hours": 1,
            "fine_exposure_gbp": 17500000,
        },
        {
            "control_id": "NS-002",
            "name": "TLS Certificate Expiry",
            "description": "Verify TLS certificates are not expiring within 30 days",
            "category": "network_security",
            "runner_module": "app.control_runners.network.check_tls_certificates",
            "iso27001_clause": "A.10.1.1",
            "nist_csf": "PR.DS-2",
            "soc2_criteria": "CC6.7",
            "cyber_essentials": "CE-NS-2",
            "severity": "high",
            "frequency_hours": 24,
            "fine_exposure_gbp": 5000000,
        },
        {
            "control_id": "NS-003",
            "name": "Firewall Rule Review",
            "description": "Verify firewall rules follow least privilege and block unnecessary traffic",
            "category": "network_security",
            "runner_module": "app.control_runners.network.check_firewall_rules",
            "iso27001_clause": "A.13.1.2",
            "nist_csf": "PR.AC-5",
            "soc2_criteria": "CC6.6",
            "cyber_essentials": "CE-NS-3",
            "severity": "high",
            "frequency_hours": 6,
            "fine_exposure_gbp": 5000000,
        },
        # Data Protection
        {
            "control_id": "DP-001",
            "name": "Disk Encryption Status",
            "description": "Verify full disk encryption is enabled on all volumes",
            "category": "data_protection",
            "runner_module": "app.control_runners.data.check_disk_encryption",
            "iso27001_clause": "A.10.1.1",
            "nist_csf": "PR.DS-1",
            "soc2_criteria": "CC6.1",
            "cyber_essentials": "CE-DP-1",
            "severity": "critical",
            "frequency_hours": 12,
            "fine_exposure_gbp": 17500000,
        },
        {
            "control_id": "DP-002",
            "name": "Backup Verification",
            "description": "Verify backups are running and restoration tested within 90 days",
            "category": "data_protection",
            "runner_module": "app.control_runners.data.check_backups",
            "iso27001_clause": "A.12.3.1",
            "nist_csf": "PR.IP-4",
            "soc2_criteria": "A1.2",
            "cyber_essentials": "CE-DP-2",
            "severity": "high",
            "frequency_hours": 24,
            "fine_exposure_gbp": 10000000,
        },
        # Logging & Monitoring
        {
            "control_id": "LM-001",
            "name": "Log Retention Policy",
            "description": "Verify security logs are retained for legally required minimum period (1 year for UK GDPR)",
            "category": "logging_monitoring",
            "runner_module": "app.control_runners.monitoring.check_log_retention",
            "iso27001_clause": "A.12.4.1",
            "nist_csf": "DE.CM-1",
            "soc2_criteria": "CC7.2",
            "cyber_essentials": "CE-LM-1",
            "severity": "high",
            "frequency_hours": 24,
            "fine_exposure_gbp": 17500000,
        },
        {
            "control_id": "LM-002",
            "name": "Security Event Alerting",
            "description": "Verify SIEM or alerting is configured for critical security events",
            "category": "logging_monitoring",
            "runner_module": "app.control_runners.monitoring.check_alerting",
            "iso27001_clause": "A.16.1.2",
            "nist_csf": "DE.AE-1",
            "soc2_criteria": "CC7.3",
            "cyber_essentials": "CE-LM-2",
            "severity": "high",
            "frequency_hours": 6,
            "fine_exposure_gbp": 5000000,
        },
        # Vulnerability Management
        {
            "control_id": "VM-001",
            "name": "Patch Management",
            "description": "Verify critical and high severity patches are applied within SLA (30 days)",
            "category": "vulnerability_management",
            "runner_module": "app.control_runners.vuln.check_patch_status",
            "iso27001_clause": "A.12.6.1",
            "nist_csf": "PR.IP-12",
            "soc2_criteria": "CC7.1",
            "cyber_essentials": "CE-VM-1",
            "severity": "critical",
            "frequency_hours": 6,
            "fine_exposure_gbp": 17500000,
        },
        {
            "control_id": "VM-002",
            "name": "Antivirus / EDR Coverage",
            "description": "Verify endpoint protection is installed and updated on all managed devices",
            "category": "vulnerability_management",
            "runner_module": "app.control_runners.vuln.check_endpoint_protection",
            "iso27001_clause": "A.12.2.1",
            "nist_csf": "DE.CM-4",
            "soc2_criteria": "CC6.8",
            "cyber_essentials": "CE-VM-2",
            "severity": "high",
            "frequency_hours": 12,
            "fine_exposure_gbp": 5000000,
        },
    ]

    for ctrl_data in controls:
        result = await session.execute(
            select(ControlCatalog).where(ControlCatalog.control_id == ctrl_data["control_id"])
        )
        if not result.scalar_one_or_none():
            ctrl = ControlCatalog(**ctrl_data)
            session.add(ctrl)

    await session.commit()
    logger.info("Control catalog seeded", count=len(controls))


async def seed_superuser(session: AsyncSession):
    """Create initial CISO superuser account."""
    from app.models.user import User
    from sqlalchemy import select

    result = await session.execute(
        select(User).where(User.email == settings.FIRST_SUPERUSER_EMAIL)
    )
    if not result.scalar_one_or_none():
        user = User(
            email=settings.FIRST_SUPERUSER_EMAIL,
            full_name=settings.FIRST_SUPERUSER_NAME,
            hashed_password=get_password_hash(settings.FIRST_SUPERUSER_PASSWORD),
            role=UserRole.CISO.value,
            is_active=True,
            is_superuser=True,
        )
        session.add(user)
        await session.commit()
        logger.info("Superuser created", email=settings.FIRST_SUPERUSER_EMAIL)
    else:
        logger.info("Superuser already exists")


async def seed_demo_users(session: AsyncSession):
    """Seed one demo user per non-CISO RBAC role for out-of-box demo experience."""
    from app.models.user import User
    from sqlalchemy import select

    demo_users = [
        {
            "email": "board@sentinel.local",
            "full_name": "Diana Hartwell",
            "password": "Board@Sentinel2024",
            "role": UserRole.BOARD_MEMBER.value,
            "department": "Executive Board",
        },
        {
            "email": "riskowner@sentinel.local",
            "full_name": "Marcus Chen",
            "password": "Risk@Sentinel2024",
            "role": UserRole.RISK_OWNER.value,
            "department": "Information Security",
        },
        {
            "email": "auditor@sentinel.local",
            "full_name": "Priya Nair",
            "password": "Audit@Sentinel2024",
            "role": UserRole.INTERNAL_AUDITOR.value,
            "department": "Internal Audit",
        },
        {
            "email": "readonly@sentinel.local",
            "full_name": "James Fletcher",
            "password": "Read@Sentinel2024",
            "role": UserRole.READ_ONLY.value,
            "department": "Operations",
        },
    ]

    created = 0
    for u_data in demo_users:
        result = await session.execute(select(User).where(User.email == u_data["email"]))
        if not result.scalar_one_or_none():
            user = User(
                email=u_data["email"],
                full_name=u_data["full_name"],
                hashed_password=get_password_hash(u_data["password"]),
                role=u_data["role"],
                department=u_data["department"],
                is_active=True,
                is_superuser=False,
            )
            session.add(user)
            created += 1

    await session.commit()
    logger.info("Demo users seeded", created=created)


async def seed_policies(session: AsyncSession):
    """Seed default policy templates for NIST CSF, EU AI Act, and DORA."""
    from app.models.governance import Policy
    from app.models.user import User
    from sqlalchemy import select

    # Get the superuser CISO to act as author
    ciso_user = await session.execute(
        select(User).where(User.email == settings.FIRST_SUPERUSER_EMAIL)
    )
    ciso = ciso_user.scalar_one_or_none()
    ciso_id = ciso.id if ciso else 1

    policies = [
        {
            "policy_ref": "POL-0001",
            "title": "NIST CSF 2.0 — Identification & Access Management Policy",
            "category": "access_control",
            "description": "Defines access control requirements, MFA enforcement, and privileged account lifecycle in accordance with NIST CSF 2.0 PR.AC.",
            "content": (
                "# NIST CSF 2.0 Access Control Policy\n\n"
                "## 1. Purpose\n"
                "To ensure that access to system resources is restricted to authorized users and processes, "
                "protecting the confidentiality, integrity, and availability of organization systems.\n\n"
                "## 2. Policy Requirements\n"
                "- **Multi-Factor Authentication (MFA):** Mandatory for all remote access, admin accounts, and critical database endpoints.\n"
                "- **Password Complexity:** Minimum 12 characters, requiring uppercase, lowercase, numbers, and symbols.\n"
                "- **Inactivity Timeout:** Sessions must terminate automatically after 15 minutes of inactivity.\n"
                "- **Privileged Access Review:** Sudo/Admin memberships must be reviewed and re-approved quarterly. "
                "Any account inactive for more than 90 days must be disabled immediately."
            ),
            "framework_references": ["NIST_CSF", "ISO27001", "SOC2"],
            "status": "published",
            "version": "1.0",
        },
        {
            "policy_ref": "POL-0002",
            "title": "EU AI Act — Ethical AI Governance & Compliance Policy",
            "category": "information_security",
            "description": "Establishes risk assessment and guardrail requirements for AI systems, including LLMs, in compliance with the EU AI Act.",
            "content": (
                "# EU AI Act Compliance & Governance Policy\n\n"
                "## 1. Purpose\n"
                "To govern the deployment, integration, and use of Artificial Intelligence (AI) and Large Language Models (LLMs) "
                "within the organization, ensuring safety, transparency, and data protection in alignment with EU regulatory mandates.\n\n"
                "## 2. Risk Classification\n"
                "- All AI systems must undergo a mandatory Risk Assessment (NIST AI RMF / EU Classification) prior to production deployment.\n"
                "- High-Risk systems (e.g. biometrics, critical infrastructure, recruitment) must implement permanent human-in-the-loop controls.\n\n"
                "## 3. Input & Output Guardrails\n"
                "- **DLP Scanning:** All prompts and responses must be scanned in real-time to prevent the leakage of PII or Intellectual Property.\n"
                "- **Prompt Injection Protection:** Guardrails must be active to detect and block malicious prompt overrides.\n"
                "- **Audit Logging:** Logs of all user interactions with AI models must be retained securely for 6 months."
            ),
            "framework_references": ["EU_AI_ACT", "NIST_AI_RMF"],
            "status": "published",
            "version": "1.0",
        },
        {
            "policy_ref": "POL-0003",
            "title": "DORA — ICT Risk Management & Digital Operational Resilience Policy",
            "category": "disaster_recovery",
            "description": "Provides a framework for ICT risk management, incident classification, and digital operational resilience testing in compliance with DORA.",
            "content": (
                "# DORA ICT Risk Management Policy\n\n"
                "## 1. Purpose\n"
                "To establish a robust Digital Operational Resilience framework that protects our systems and services "
                "against ICT-related disruptions, in compliance with the EU Digital Operational Resilience Act (DORA).\n\n"
                "## 2. Key Controls\n"
                "- **ICT Risk Assessment:** Continuous automated vulnerability scans and firewall rule review on critical infrastructure.\n"
                "- **Third-Party Provider Management:** Security and resilience audits of key third-party ICT service providers (e.g. cloud hosting) before contract renewal.\n"
                "- **Resilience Testing:** Mandatory annual penetration testing and disaster recovery drills.\n"
                "- **Incident Reporting:** Any major ICT incident must be classified and reported to the CISO within 4 hours."
            ),
            "framework_references": ["DORA", "ISO27001"],
            "status": "published",
            "version": "1.0",
        }
    ]

    for p_data in policies:
        existing = await session.execute(
            select(Policy).where(Policy.policy_ref == p_data["policy_ref"])
        )
        if not existing.scalar_one_or_none():
            p = Policy(
                policy_ref           = p_data["policy_ref"],
                title                = p_data["title"],
                category             = p_data["category"],
                description          = p_data["description"],
                content              = p_data["content"],
                framework_references = p_data["framework_references"],
                status               = p_data["status"],
                version              = p_data["version"],
                author_id            = ciso_id,
            )
            session.add(p)

    await session.commit()
    logger.info("Compliance policies (NIST/EU AI/DORA) seeded")


async def seed_risks(session: AsyncSession):
    """Seed some initial FAIR risks so the risk register is populated by default."""
    from app.models.risk import Risk
    from app.models.user import User
    from app.services.risk_engine import risk_engine
    from sqlalchemy import select, func

    # Get superuser
    ciso_user = await session.execute(
        select(User).where(User.email == settings.FIRST_SUPERUSER_EMAIL)
    )
    ciso = ciso_user.scalar_one_or_none()
    ciso_id = ciso.id if ciso else 1

    existing_count = await session.execute(select(func.count(Risk.id)))
    if existing_count.scalar() == 0:
        # Seed Risk 1: Weak Password Policy
        calc1 = risk_engine.calculate_risk(
            asset_value_gbp=250_000,
            threat_event_frequency=5.0,
            vulnerability_probability=0.6,
            primary_loss_magnitude_gbp=125_000,
            secondary_loss_magnitude_gbp=62_500,
            regulatory_fine_exposure_gbp=50_000,
        )

        # Seed Risk 2: Exposed Database Port
        calc2 = risk_engine.calculate_risk(
            asset_value_gbp=1_200_000,
            threat_event_frequency=12.0,
            vulnerability_probability=0.8,
            primary_loss_magnitude_gbp=600_000,
            secondary_loss_magnitude_gbp=300_000,
            regulatory_fine_exposure_gbp=500_000,
        )

        # Seed Risk 3: AI Prompt Injection Data Leakage
        calc3 = risk_engine.calculate_risk(
            asset_value_gbp=800_000,
            threat_event_frequency=8.0,
            vulnerability_probability=0.5,
            primary_loss_magnitude_gbp=400_000,
            secondary_loss_magnitude_gbp=200_000,
            regulatory_fine_exposure_gbp=150_000,
        )

        risks = [
            Risk(
                risk_ref="RISK-0001",
                title="Risk of Unauthorized System Access due to Weak Password Policies",
                description="The password policy allows short (less than 12 characters) passwords without rotation, increasing brute force susceptibility.",
                category="cyber",
                source="control_runner",
                source_control_id="AC-001",
                frameworks_impacted=["ISO27001-A.9.4.3", "NIST-PR.AC-1", "SOC2-CC6.1"],
                asset_name="User Authentication Directory",
                asset_type="database",
                asset_value_gbp=250_000,
                data_sensitivity="confidential",
                threat_event_frequency=5.0,
                vulnerability_probability=0.6,
                primary_loss_magnitude_gbp=125_000,
                secondary_loss_magnitude_gbp=62_500,
                regulatory_fine_exposure_gbp=50_000,
                annualised_loss_expectancy_gbp=calc1["ale_mean_gbp"],
                ale_10th_percentile_gbp=calc1["ale_10th_percentile_gbp"],
                ale_90th_percentile_gbp=calc1["ale_90th_percentile_gbp"],
                exploitation_probability_12m=calc1["exploitation_probability_12m"],
                last_monte_carlo_run=datetime.utcnow(),
                severity=calc1["severity"],
                status="open",
                owner_id=ciso_id,
                raised_by_id=ciso_id,
            ),
            Risk(
                risk_ref="RISK-0002",
                title="Risk of Data Exfiltration via Publicly Exposed Database Port",
                description="Database ports (e.g. 5432, 3306) exposed directly to the internet, allowing external login attempts and exploits.",
                category="cyber",
                source="control_runner",
                source_control_id="NS-001",
                frameworks_impacted=["ISO27001-A.13.1.1", "NIST-PR.AC-5", "SOC2-CC6.6"],
                asset_name="Production Database Cluster",
                asset_type="database",
                asset_value_gbp=1_200_000,
                data_sensitivity="restricted",
                threat_event_frequency=12.0,
                vulnerability_probability=0.8,
                primary_loss_magnitude_gbp=600_000,
                secondary_loss_magnitude_gbp=300_000,
                regulatory_fine_exposure_gbp=500_000,
                annualised_loss_expectancy_gbp=calc2["ale_mean_gbp"],
                ale_10th_percentile_gbp=calc2["ale_10th_percentile_gbp"],
                ale_90th_percentile_gbp=calc2["ale_90th_percentile_gbp"],
                exploitation_probability_12m=calc2["exploitation_probability_12m"],
                last_monte_carlo_run=datetime.utcnow(),
                severity=calc2["severity"],
                status="open",
                owner_id=ciso_id,
                raised_by_id=ciso_id,
            ),
            Risk(
                risk_ref="RISK-0003",
                title="Risk of PII Leakage due to Unprotected AI LLM Prompts & Responses",
                description="Organizational integration of generative AI models without guardrail scanning (DLP), exposing system logs or chat history.",
                category="cyber",
                source="manual",
                frameworks_impacted=["EU_AI_ACT", "NIST_AI_RMF"],
                asset_name="AI LLM Integration Service",
                asset_type="application",
                asset_value_gbp=800_000,
                data_sensitivity="confidential",
                threat_event_frequency=8.0,
                vulnerability_probability=0.5,
                primary_loss_magnitude_gbp=400_000,
                secondary_loss_magnitude_gbp=200_000,
                regulatory_fine_exposure_gbp=150_000,
                annualised_loss_expectancy_gbp=calc3["ale_mean_gbp"],
                ale_10th_percentile_gbp=calc3["ale_10th_percentile_gbp"],
                ale_90th_percentile_gbp=calc3["ale_90th_percentile_gbp"],
                exploitation_probability_12m=calc3["exploitation_probability_12m"],
                last_monte_carlo_run=datetime.utcnow(),
                severity=calc3["severity"],
                status="open",
                owner_id=ciso_id,
                raised_by_id=ciso_id,
            )
        ]
        session.add_all(risks)
        await session.commit()
        logger.info("Default GRC risks seeded successfully")


async def init_db():
    """Main database initialisation routine."""
    from app.models import user, compliance, control, risk, evidence, governance, threat, ai_security  # noqa

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    AsyncSession_ = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        logger.info("Creating database tables...")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Tables created")

    async with AsyncSession_() as session:
        await create_timescale_hypertables(session)
        await create_performance_indexes(session)   # ← NEW: composite indexes
        await seed_frameworks(session)
        await seed_control_catalog(session)
        await seed_superuser(session)
        await seed_demo_users(session)
        await seed_policies(session)
        await seed_risks(session)

    await engine.dispose()
    logger.info("Database initialisation complete")



if __name__ == "__main__":
    asyncio.run(init_db())
