# Kibana dashboards

Drop your exported Kibana saved-object NDJSON files in this directory.

The setup script (`scripts/setup.sh`) auto-imports a file named exactly:

```
bluestack-saved-objects.ndjson
```

To export from a running Kibana:

1. Stack Management → Saved Objects
2. Select the dashboards / visualizations / saved searches you want
3. **Export** (top-right) → save as `bluestack-saved-objects.ndjson`
4. Re-run `./scripts/setup.sh` — it will pick up the file and `_import?overwrite=true` it.

This keeps dashboards version-controlled alongside the pipelines that feed them.
