# Threat Intelligence Aggregator API

REST API for aggregating and analyzing data from multiple threat intelligence sources. Provides a unified interface for checking IP addresses, domains, and APT groups.

## Features

- **Multiple TI Sources**: VirusTotal, AbuseIPDB, AlienVault OTX, IPQualityScore
- **Redis Caching**: Reduces API calls and improves response time
- **Rate Limiting**: PostgreSQL-based API usage control
- **API Key Authentication**: User authorization and accounting system
- **High Performance**: Built with Go and Gin framework

## Prerequisites

- Go 1.21+
- PostgreSQL (Neon Database)
- Redis
- API keys from:
  - VirusTotal
  - AbuseIPDB
  - AlienVault OTX
  - IPQualityScore

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/threat-intelligence-api.git
cd threat-intelligence-api
```

2. Install dependencies:
```bash
go mod download
```

3. Create `.env` file:
```env
NEON_DATABASE_URL=postgresql://user:password@host/database
REDIS_URL=redis://localhost:6379
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
ALIENVAULT_API_KEY=your_alienvault_key
IPQUALITYSCORE_API_KEY=your_ipqs_key
```

4. Create database table:
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key VARCHAR(64) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    rate_limit_per_day INTEGER DEFAULT 100,
    active BOOLEAN DEFAULT true
);

-- Add test user
INSERT INTO users (api_key, username, rate_limit_per_day, active) 
VALUES ('test-api-key-123', 'test_user', 1000, true);
```

## Running
```bash
go run main.go
```

API will be available at `http://localhost:8080`

## API Endpoints

### 1. Check IP Address
```http
GET /api/v1/check/ip/:ip
```

**Example:**
```bash
curl -H "X-API-Key: test-api-key-123" http://localhost:8080/api/v1/check/ip/8.8.8.8
```

**Response:**
```json
{
  "virustotal": {},
  "abuseipdb": {},
  "alienvault_otx": {},
  "ipqualityscore": {}
}
```

### 2. Check Domain
```http
GET /api/v1/check/domain/:domain
```

**Example:**
```bash
curl -H "X-API-Key: test-api-key-123" http://localhost:8080/api/v1/check/domain/example.com
```

**Response:**
```json
{
  "virustotal": {},
  "alienvault_otx": {}
}
```

### 3. APT Group Information
```http
GET /api/v1/check/apt/:apt
```

**Example:**
```bash
curl -H "X-API-Key: test-api-key-123" http://localhost:8080/api/v1/check/apt/APT29
```

**Response:**
```json
{
  "alienvault_otx": {
    "count": 127,
    "results": []
  }
}
```

## Authentication

All requests require the `X-API-Key` header:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/check/...
```

## Rate Limiting

- Limit is set per API key in the database
- Counter resets daily
- When exceeded: `HTTP 429 Too Many Requests`

## Caching

- **IP/Domain**: 12 hours
- **APT**: 24 hours
- Header `X-Cache-Status: HIT` indicates cached response

## Project Structure
```
.
├── main.go           # Main application file
├── .env              # Environment variables
├── go.mod            # Go modules
└── README.md         # Documentation
```