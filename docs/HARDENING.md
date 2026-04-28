# Hardening BlueStack

The default config is a lab kit — security is *off* on purpose so the stack starts cleanly on a laptop with no certificate-juggling. Before exposing this stack to anything you care about, work through this list.

## 1. Turn on Elasticsearch security

```yaml
# elasticsearch/config/elasticsearch.yml
xpack.security.enabled: true
xpack.security.http.ssl.enabled: true
xpack.security.transport.ssl.enabled: true
```

Set the `elastic` superuser password (one-shot inside the running container):

```bash
docker exec -it bluestack-elasticsearch \
  bin/elasticsearch-reset-password -u elastic -i
```

Then update Kibana and Logstash to authenticate. Kibana wants its own service account user (`kibana_system`); generate one with:

```bash
docker exec -it bluestack-elasticsearch \
  bin/elasticsearch-service-tokens create elastic/kibana bluestack-kibana
```

## 2. Don't bind to all interfaces

`docker-compose.yml` already binds host ports to `127.0.0.1`. If you need LAN access, put a reverse proxy with TLS in front (Caddy or nginx). Do *not* simply change `127.0.0.1` to `0.0.0.0` and call it done.

## 3. Index Lifecycle Management

The bundled index template is unbounded — every day creates a new `bluestack-<tool>-YYYY.MM.DD` index forever. Add an ILM policy that rolls and deletes after, e.g., 30 days:

```bash
curl -X PUT 'http://localhost:9200/_ilm/policy/bluestack-30d' \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
      "phases": {
        "hot":   { "actions": { "rollover": { "max_age": "1d" } } },
        "delete":{ "min_age": "30d", "actions": { "delete": {} } }
      }
    }
  }'
```

Then attach it to the index template by adding `"index.lifecycle.name": "bluestack-30d"` to `scripts/index-template.json`.

## 4. Logstash credentials in env, not config

If you enable Elasticsearch auth, do not paste the password into `logstash/pipeline/*.conf`. Use environment variables and reference them in the output block:

```
output {
  elasticsearch {
    hosts    => ["https://elasticsearch:9200"]
    user     => "${ES_USER}"
    password => "${ES_PASSWORD}"
    ssl      => true
    cacert   => "/usr/share/logstash/config/ca.crt"
  }
}
```

Wire `ES_USER` / `ES_PASSWORD` through `docker-compose.yml` from the `.env` file.

## 5. Resource limits

The default `1g` Elasticsearch heap is enough for sample data but will OOM under a busy ingest. Raise `ES_HEAP` in `.env` and add a Docker memory limit so it doesn't take down the host:

```yaml
elasticsearch:
  mem_limit: 4g
```

## 6. Audit logging

For an actual SOC use case, enable Elasticsearch audit logging so you have a paper trail of who queried what — meaningful only once auth is on.

```yaml
xpack.security.audit.enabled: true
```

## 7. Don't ship the lab `.env`

Anything in `.env` is gitignored, but double-check before pushing. Production credentials never belong in the compose file.
