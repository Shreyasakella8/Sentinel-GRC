#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# SENTINEL-GRC — One-Command Startup Script
# Usage: ./start.sh
# ══════════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'

echo ""
echo -e "${RED}  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ${NC}"
echo -e "${RED}  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ${NC}"
echo -e "${RED}  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ${NC}"
echo -e "${RED}  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ${NC}"
echo -e "${RED}  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗${NC}"
echo -e "${RED}  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝${NC}"
echo ""
echo -e "${CYAN}  Enterprise Continuous Controls Monitoring & Risk Intelligence Platform${NC}"
echo -e "${WHITE}  Version 1.0.0 — All modules local — Zero cloud dependency${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found. Install Docker Desktop from https://docker.com${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
    echo -e "${RED}✗ Docker Compose not found.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker detected${NC}"

# Determine compose command
if docker compose version &> /dev/null 2>&1; then
    COMPOSE="docker compose"
else
    COMPOSE="docker-compose"
fi

# Copy .env if needed
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠ No .env found — copying from .env.example${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ .env created — edit it to customise settings${NC}"
fi

echo ""
echo -e "${CYAN}► Starting SENTINEL-GRC services...${NC}"
echo ""

# Build and start
$COMPOSE up --build -d

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✓ SENTINEL-GRC is starting up!${NC}"
echo ""
echo -e "  ${WHITE}Waiting for services to be healthy (~30 seconds)...${NC}"
sleep 10

# Wait for backend
echo -e "  ${CYAN}Checking backend health...${NC}"
for i in {1..30}; do
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓ Backend is healthy${NC}"
        break
    fi
    sleep 2
    if [ $i -eq 30 ]; then
        echo -e "  ${YELLOW}⚠ Backend may still be starting. Check: docker compose logs backend${NC}"
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}  🚀 SENTINEL-GRC IS RUNNING${NC}"
echo ""
echo -e "  ${WHITE}Frontend (React Dashboard):${NC}    ${CYAN}http://localhost:3000${NC}"
echo -e "  ${WHITE}Backend API:${NC}                    ${CYAN}http://localhost:8000${NC}"
echo -e "  ${WHITE}API Documentation:${NC}              ${CYAN}http://localhost:8000/api/docs${NC}"
echo -e "  ${WHITE}MinIO Evidence Store:${NC}           ${CYAN}http://localhost:9001${NC}"
echo ""
echo -e "  ${WHITE}Default Login:${NC}"
echo -e "  ${CYAN}Email:${NC}    admin@sentinel.local"
echo -e "  ${CYAN}Password:${NC} SentinelAdmin@2024"
echo ""
echo -e "  ${WHITE}MinIO Console:${NC}"
echo -e "  ${CYAN}User:${NC}     sentinel_minio"
echo -e "  ${CYAN}Password:${NC} sentinel_minio_secret"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  ${YELLOW}Quick Start:${NC}"
echo -e "  1. Open ${CYAN}http://localhost:3000${NC} and log in"
echo -e "  2. Go to ${WHITE}Controls${NC} → click ${WHITE}Run Full Sweep Now${NC} to execute all 10 control runners"
echo -e "  3. Go to ${WHITE}Threats${NC} → click ${WHITE}Refresh All Feeds${NC} to ingest NVD CVEs"
echo -e "  4. Go to ${WHITE}Reports${NC} → generate Board / Auditor / Technical reports"
echo ""
echo -e "  ${YELLOW}Useful Commands:${NC}"
echo -e "  ${CYAN}./stop.sh${NC}                    Stop all services"
echo -e "  ${CYAN}docker compose logs -f${NC}       Stream all logs"
echo -e "  ${CYAN}docker compose logs backend${NC}  Backend logs only"
echo ""
