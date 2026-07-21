# SENTINEL-GRC Deployment Safety & Rollback Guide

## 1. Pre-deployment Checklist
Before deploying the v2 performance updates to production, ensure the following steps are taken:

- [ ] **Run the full test suite**: `pytest tests/ -v` (Verify all tests pass)
- [ ] **Verify Database Indexes**: Run `SELECT * FROM pg_indexes WHERE indexname LIKE 'idx_%';` and verify `idx_evidence_control_collected`, `idx_risk_scores_risk_recorded`, and `idx_control_results_control_executed` exist.
- [ ] **Dry-run migrations**: Run `alembic upgrade head --sql` to verify DDL statements.
- [ ] **Backup the database**: Run a full dump: `pg_dump -U sentinel sentinel_grc | gzip > backup_$(date +%F).sql.gz`

## 2. Feature Flags
To enable zero-downtime rollback, several new features are gated by feature flags in `.env`.

| Feature Flag | Default | Description |
|---|---|---|
| `ENABLE_PAGINATION` | `True` | Controls whether `/risks` and `/evidence` use Cursor/OFFSET pagination. If set to `False`, endpoints revert to legacy unbounded list behavior. |
| `ENABLE_EVIDENCE_DEDUP` | `True` | If `False`, disables the new content-hash deduplication for MinIO storage, reverting to uploading a new blob every time. |
| `ENABLE_AUDIT_MIDDLEWARE` | `True` | If `False`, disables the async audit logging of mutating requests. |

## 3. Rollback Procedure
If the deployment causes critical issues, follow these steps to rollback:

### Soft Rollback (via Feature Flags)
If the issue is isolated to pagination, evidence deduplication, or audit middleware:
1. Edit the `.env` file to set the problematic flag to `False`.
2. Restart the API containers (e.g. `docker compose restart api`).
3. No code revert is necessary.

### Full Rollback
If the application fails to start or there are systemic issues:
1. Revert the code: `git revert <deployment-commit>`
2. Re-deploy the previous image: `docker pull your-registry/sentinel-grc:v1.x && docker compose up -d`
3. Downgrade database if required: `alembic downgrade -1`
4. Check system health: `curl http://localhost:8000/health/deep`

## 4. Performance Verification
Post-deployment, monitor the following:
- Verify `/health/deep` returns 200 OK.
- Run `scripts/performance_baseline.py` in the production environment to measure query response times.
- Monitor PostgreSQL connection pools (target: under `DB_POOL_SIZE` + `DB_MAX_OVERFLOW`).
- Monitor Celery workers to ensure tasks are prefetched properly and not starving.
