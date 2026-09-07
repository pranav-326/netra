#!/usr/bin/env bash
# ==============================================================================
# Netra Infrastructure Health Check Script
# ==============================================================================
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Testing Netra Layer 8 Infrastructure Services...${NC}\n"

# 1. PostgreSQL
echo -n "Checking PostgreSQL (Port 5432)... "
if docker compose exec postgres pg_isready -U netra_admin -d netra_db > /dev/null 2>&1; then
    echo -e "${GREEN}[OK] PostgreSQL is healthy and accepting queries.${NC}"
else
    echo -e "${RED}[FAIL] PostgreSQL is not reachable or healthy.${NC}"
fi

# 2. Redis
echo -n "Checking Redis (Port 6379)... "
if [[ "$(docker compose exec redis redis-cli ping 2>/dev/null)" =~ "PONG" ]]; then
    echo -e "${GREEN}[OK] Redis is healthy and responding to PING.${NC}"
else
    echo -e "${RED}[FAIL] Redis is not reachable or healthy.${NC}"
fi

# 3. OpenSearch
echo -n "Checking OpenSearch (Port 9200)... "
if curl -s -f http://localhost:9200/_cluster/health > /dev/null 2>&1; then
    STATUS=$(curl -s http://localhost:9200/_cluster/health | grep -o '"status":"[^"]*"' || echo "status: ok")
    echo -e "${GREEN}[OK] OpenSearch is healthy (${STATUS}).${NC}"
else
    echo -e "${RED}[FAIL] OpenSearch is not responding.${NC}"
fi

# 4. Neo4j
echo -n "Checking Neo4j (Port 7474 / 7687)... "
if curl -s -f http://localhost:7474/ > /dev/null 2>&1; then
    echo -e "${GREEN}[OK] Neo4j HTTP/Bolt interface is healthy.${NC}"
else
    echo -e "${RED}[FAIL] Neo4j is not responding.${NC}"
fi

# 5. MinIO
echo -n "Checking MinIO (Port 9000 / 9001)... "
if curl -s -f http://localhost:9000/minio/health/live > /dev/null 2>&1; then
    echo -e "${GREEN}[OK] MinIO Object Store is healthy.${NC}"
else
    echo -e "${RED}[FAIL] MinIO is not responding.${NC}"
fi

echo -e "\n${GREEN}Infrastructure health check completed.${NC}"
