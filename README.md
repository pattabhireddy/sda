# RHEL Patch Monitor Agent

An Azure Function (Python, Timer-triggered) that monitors Red Hat Security Advisories and sends email notifications when new patches are released.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Azure Function (Timer Trigger — daily 08:00 UTC)        │
│                                                           │
│  1. Read last check date  ──► Azure Blob Storage          │
│  2. Poll RHEL Security Data API                           │
│  3. If new advisories found ──► Send Email (SMTP)         │
│  4. Update last check date ──► Azure Blob Storage         │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
patch-monitor-agent/
├── function_app.py          # Azure Function entry point (timer trigger)
├── patch_checker.py         # RHEL Security Data API polling
├── notifier.py              # Email notification via SMTP
├── state_manager.py         # Persists last check date in Azure Blob Storage
├── requirements.txt         # Python dependencies
├── host.json                # Azure Functions host config
└── local.settings.json      # Local dev environment variables (DO NOT COMMIT)
```

---

## Setup

### Prerequisites
- Python 3.11+
- [Azure Functions Core Tools v4](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
- Azure Subscription with:
  - Azure Function App (Python, Consumption or Flex plan)
  - Azure Storage Account (for state + AzureWebJobsStorage)

### 1. Configure environment variables

Edit `local.settings.json` (local) or set App Settings in the Azure Function App:

| Variable                          | Description                                      |
|-----------------------------------|--------------------------------------------------|
| `AZURE_STORAGE_CONNECTION_STRING` | Connection string for state blob storage         |
| `SMTP_HOST`                       | SMTP server (e.g. `smtp.office365.com`)          |
| `SMTP_PORT`                       | SMTP port (default: `587`)                       |
| `SMTP_USERNAME`                   | Sender email address                             |
| `SMTP_PASSWORD`                   | App password / SMTP password                     |
| `NOTIFY_TO_EMAIL`                 | Recipient(s), comma-separated                    |
| `PATCH_MONITOR_CRON`              | Cron schedule (default: `0 0 8 * * *` = 08:00 UTC) |

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run locally

```bash
func start
```

### 4. Deploy to Azure

```bash
# Create Function App (if not already created)
az functionapp create \
  --resource-group <YOUR_RG> \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name <YOUR_FUNCTION_APP_NAME> \
  --storage-account <YOUR_STORAGE_ACCOUNT>

# Deploy
func azure functionapp publish <YOUR_FUNCTION_APP_NAME>
```

---

## How It Works

1. **Timer fires** at the configured schedule (default: daily 08:00 UTC).
2. **Reads last check date** from `patch-monitor-state/last_check_state.json` in Azure Blob Storage.
3. **Polls** `https://access.redhat.com/labs/securitydataapi/cvrf.json?after=<last_check_date>`.
4. **If new advisories exist**, sends an HTML + plain-text email listing each advisory with:
   - Advisory ID (linked to Red Hat errata page)
   - Severity (color-coded)
   - Synopsis
   - Release date
   - Associated CVEs
5. **Updates** the last check date in Blob Storage to today.
6. **If email fails**, state is NOT updated — the agent retries on the next run.

---

## Customizing the Schedule

Change `PATCH_MONITOR_CRON` app setting using Azure NCRONTAB format:
`{second} {minute} {hour} {day} {month} {day-of-week}`

Examples:
- Every day at 08:00 UTC: `0 0 8 * * *`
- Every 6 hours: `0 0 */6 * * *`
- Every Monday at 09:00 UTC: `0 0 9 * * 1`

---

## Security Notes

- Never commit `local.settings.json` to version control (it contains secrets).
- Use [Azure Key Vault references](https://learn.microsoft.com/azure/app-service/app-service-key-vault-references) for production secrets.
- The agent only makes outbound GET requests to the Red Hat public API — no inbound surface.
