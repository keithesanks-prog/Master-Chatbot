# Master Agent - User Guide

**Quick Reference Guide for Service Management**

---

## Quick Start

### Start Service (Development)
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Start Service (Production)
```bash
sudo systemctl start master-agent
```

---

## Service Management Commands

### Using systemd (Recommended for Production)

| Command | Description |
|---------|-------------|
| `sudo systemctl start master-agent` | Start the service |
| `sudo systemctl stop master-agent` | Stop the service (graceful shutdown - fail-safe) |
| `sudo systemctl restart master-agent` | Restart the service |
| `sudo systemctl reload master-agent` | Reload the service (graceful reload) |
| `sudo systemctl status master-agent` | Check service status and recent logs |
| `sudo systemctl enable master-agent` | Enable service to start on boot |
| `sudo systemctl disable master-agent` | Disable service from starting on boot |

### Using Management Script

```bash
# Make script executable (first time only)
chmod +x deployment/manage-service.sh

# Available commands
./deployment/manage-service.sh start      # Start service
./deployment/manage-service.sh stop       # Stop service (graceful shutdown - fail-safe)
./deployment/manage-service.sh restart    # Restart service
./deployment/manage-service.sh reload     # Reload service (graceful)
./deployment/manage-service.sh status     # Show status and recent logs
./deployment/manage-service.sh install    # Install service file
./deployment/manage-service.sh help       # Show help message
```

---

## Installation

### First-Time Setup

**1. Install the service file:**
```bash
sudo ./deployment/manage-service.sh install
```

**2. Enable service on boot (optional):**
```bash
sudo systemctl enable master-agent.service
```

**3. Start the service:**
```bash
sudo systemctl start master-agent
```

**4. Verify it's running:**
```bash
sudo systemctl status master-agent
```

---

## Common Operations

### Check Service Status
```bash
sudo systemctl status master-agent
# or
./deployment/manage-service.sh status
```

### View Recent Logs
```bash
journalctl -u master-agent -n 50 --no-pager
# or follow logs in real-time
journalctl -u master-agent -f
```

### Restart After Configuration Changes
```bash
sudo systemctl restart master-agent
# or
./deployment/manage-service.sh restart
```

### Graceful Reload (No Downtime)
```bash
sudo systemctl reload master-agent
# or
./deployment/manage-service.sh reload
```

---

## Fail-Safe Shutdown

The service implements **fail-safe shutdown** - when stopping:

✅ **New requests are rejected immediately** (503 Service Unavailable)  
✅ **In-flight requests complete gracefully**  
✅ **Waits up to 30 seconds** for requests to finish  
✅ **Prevents new data access** during shutdown  
✅ **Ensures audit logs** are written before shutdown  

**Example:**
```bash
# Stop service (triggers fail-safe shutdown)
sudo systemctl stop master-agent

# Any new requests will receive:
{
  "error": "Service Unavailable",
  "message": "Service is shutting down. Please try again later.",
  "service_state": "stopping",
  "fail_safe": true
}
```

---

## Troubleshooting

### Service Won't Start

**Check logs:**
```bash
sudo journalctl -u master-agent -n 100 --no-pager
```

**Check configuration:**
- Verify environment variables are set
- Check Gemini API key if using LLM features
- Verify port 8000 is not in use

### Service Won't Stop

**Check in-flight requests:**
```bash
sudo systemctl status master-agent
# Look for "in-flight requests remaining"
```

**Force stop (not recommended - may lose data):**
```bash
sudo systemctl kill -s KILL master-agent
```

### Service Status Shows "Failed"

**Check error logs:**
```bash
sudo journalctl -u master-agent -n 50 --no-pager | grep -i error
```

**Common causes:**
- Missing environment variables
- Port already in use
- Permission issues
- Invalid configuration

---

## Health Checks

### Check Service Health
```bash
curl http://localhost:8000/health
```

### Check Security Health
```bash
curl http://localhost:8000/health/security
```

---

## Service Configuration

### Environment Variables

Key environment variables (set in systemd service file or `.env`):

```bash
GEMINI_API_KEY=your-api-key-here
ENVIRONMENT=production
REQUIRE_TLS=true
ENFORCE_HTTPS=true
ALLOWED_ORIGINS=https://yourdomain.com
JWT_SECRET_KEY=your-secret-key
ENABLE_AUTH=true
```

### Service File Location

- **Service file:** `/etc/systemd/system/master-agent.service`
- **Working directory:** `/opt/master-agent` (configurable)
- **Logs:** Systemd journal (`journalctl -u master-agent`)

---

## API Endpoints

Once the service is running, access:

- **API Documentation:** `http://localhost:8000/docs`
- **Health Check:** `http://localhost:8000/health`
- **Security Health:** `http://localhost:8000/health/security`
- **Main Endpoint:** `POST http://localhost:8000/agent/ask`

---

## Additional Resources

- [README.md](README.md) - Full project documentation
- [SERVICE_MANAGEMENT.md](SERVICE_MANAGEMENT.md) - Detailed service management guide
- [SECURITY.md](SECURITY.md) - Security documentation
- [HEALTH_CHECK.md](HEALTH_CHECK.md) - Health check endpoint documentation

---

**Last Updated:** 2024

