# Wazuh Alert Triage integration

This bundle submits Wazuh alert JSON to SOCPOW's scoped service-key endpoint,
`POST /api/playbooks/alert_triage/run`. It maps Wazuh `rule.level` through
`wazuh_level_to_severity()` from `src/utils/wazuh_severity.py` and sends it as
`params.alert_severity`.

## Create the service user and enable API keys

Run these steps on the SOCPOW host, from the SOCPOW checkout, using the same
authentication database as the running server. The auth database path is
`AUTH_DB_PATH` when configured; otherwise it is `src/db/auth.db` relative to
the server's working directory. Pass that exact path to the migration:

```sh
cd /opt/blue-team-assistant
python src/db/migrations/013_create_api_keys.py /path/to/auth.db
```

For a server using the default database from the checkout root, run:

```sh
python src/db/migrations/013_create_api_keys.py src/db/auth.db
```

An administrator can invite users through `/api/admin/users/invite` when email
delivery is configured. For a service account without a human inbox, create an
invite directly with the existing auth helper, then accept it through the
normal endpoint. Use a unique placeholder email; delivery is not attempted by
this local helper:

```sh
export AUTH_DB_PATH=/path/to/auth.db
ADMIN_ID="$(python -c 'from src.web.auth import _connect; c=_connect(); print(c.execute("SELECT id FROM users WHERE role = ? ORDER BY id LIMIT 1", ("admin",)).fetchone()["id"]); c.close()')"
INVITE_TOKEN="$(SOCPOW_ADMIN_ID="$ADMIN_ID" python -c 'import os; from src.web.auth import create_invite_token; print(create_invite_token("wazuh-service@example.invalid", "Incident Responder", int(os.environ["SOCPOW_ADMIN_ID"])))')"
curl --fail-with-body -sS -X POST http://127.0.0.1:3003/api/auth/accept-invite \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$INVITE_TOKEN\",\"username\":\"wazuh-service\",\"password\":\"<strong-password>\"}"
unset INVITE_TOKEN ADMIN_ID
```

The invite's role is fixed as `Incident Responder`. Keep the invite token and
chosen password private. After acceptance, find the new user's numeric ID in
the SOCPOW admin user list.

## Mint and store the API key

Use an administrator bearer token to create a key for the service user's ID.
The response contains the raw key once; copy it directly into the protected
environment file and do not save it in shell history or tickets.

```sh
curl --fail-with-body -sS -X POST \
  "https://socpow.example.org/api/admin/users/<SERVICE_USER_ID>/api-keys" \
  -H 'Authorization: Bearer <ADMIN_BEARER_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"expires_in_days":90}'
```

On the Wazuh manager, create a root-owned environment file readable by the
`wazuh` group. Put the one-time key and the endpoint URL in it:

```sh
install -o root -g wazuh -m 0640 /dev/null /etc/wazuh-socpow.env
sudoedit /etc/wazuh-socpow.env
```

File contents (replace placeholders):

```sh
SOCPOW_API_URL=https://socpow.example.org/api/playbooks/alert_triage/run
SOCPOW_API_KEY=<ONE_TIME_RAW_API_KEY>
SOCPOW_SOURCE_ROOT=/opt/blue-team-assistant
```

Confirm the file ownership and mode with `chown root:wazuh
/etc/wazuh-socpow.env` and `chmod 0640 /etc/wazuh-socpow.env`. Load it into the
Wazuh manager service with `systemctl edit wazuh-manager`:

```ini
[Service]
EnvironmentFile=/etc/wazuh-socpow.env
```

Then run `systemctl daemon-reload` and restart `wazuh-manager`. The
`ossec.conf` integration block needs no key pass-through and remains unchanged.
Keep its `<name>` as `custom-socpow` and `alert_format` as `json`.

## Install and verify

Install the integration script with Wazuh's expected owner and group:

```sh
install -o root -g wazuh -m 0750 custom-socpow /var/ossec/integrations/custom-socpow
```

Keep the SOCPOW checkout available at `SOCPOW_SOURCE_ROOT`; it provides the
severity helper and the sample alerts. Verify the connection with the benign
sample after loading the environment file in a root shell:

```sh
set -a
. /etc/wazuh-socpow.env
set +a
/var/ossec/integrations/custom-socpow \
  "$SOCPOW_SOURCE_ROOT/deploy/wazuh/samples/benign_scan.json" \
  "$SOCPOW_API_URL"
```

The request is `POST /api/playbooks/alert_triage/run` with JSON shaped as
`{"params":{"alert_text":"...","alert_source":"Wazuh","alert_severity":"HIGH"}}`
and `Authorization: Bearer <SOCPOW_API_KEY>`. API-key requests do not need a
CSRF header. The script reports only success or a short error; it never prints
the API key or alert contents. A nonzero exit status means the submission
failed.

## Key rotation and revocation

Rotate the key every 90 days. Create the replacement before expiry, update
`SOCPOW_API_KEY` in `/etc/wazuh-socpow.env`, keep the file `root:wazuh` mode
`0640`, restart the manager, and verify with the benign sample. Then revoke the
old key using its user ID and key ID:

```sh
curl --fail-with-body -sS -X DELETE \
  "https://socpow.example.org/api/admin/users/<SERVICE_USER_ID>/api-keys/<OLD_KEY_ID>" \
  -H 'Authorization: Bearer <ADMIN_BEARER_TOKEN>'
```

## Request mapping

The script includes `rule.description`, `agent.name`, and available
`data.srcip`, `data.dstip`, `data.url`, and hash fields (`md5`, `sha1`,
`sha256`, `sha512`, `hash`, or `file_hash`; nested `data.hashes` is also
accepted). Wazuh supplies the configured `hook_url` as `argv[2]`; the
`SOCPOW_API_URL` environment setting takes precedence for manual invocation.
The integration does not approve a paused playbook run.
