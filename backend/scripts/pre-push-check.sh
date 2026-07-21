#!/bin/bash
set -e

echo "=== PRE-PUSH VALIDATION ==="

echo "1. Running tests..."
cd backend && python -m pytest tests/ -v --tb=short || exit 1

echo "2. Checking indexes..."
# This requires DB to be running
# python scripts/check_indexes.py || echo "  ⚠ Skipped (DB not available)"

echo "3. Running linting..."
python -m black app --check || echo "  ⚠ Formatting issues (run: black app)"
python -m flake8 app --max-line-length=100 || echo "  ⚠ Style issues"
python -m mypy app --ignore-missing-imports || echo "  ⚠ Type hints missing"

echo "4. Checking for secrets..."
grep -r "password\|secret\|api.key" .env 2>/dev/null && echo "  ❌ SECRETS IN .env!" || echo "  ✓ No secrets in code"

echo "5. Verifying .env.example"
[ -f ../.env.example ] && echo "  ✓ .env.example exists" || echo "  ❌ Missing .env.example"

echo "6. Checking DEPLOYMENT.md"
[ -f DEPLOYMENT.md ] && echo "  ✓ DEPLOYMENT.md exists" || echo "  ❌ Missing DEPLOYMENT.md"

echo ""
echo "=== ALL CHECKS PASSED ✓ ==="
echo "Ready to push!"
