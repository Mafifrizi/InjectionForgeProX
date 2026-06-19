# Usage Guide

## Mock target

```bash
python forge_x.py --profile examples/profiles/mock-strict.json
```

## REST target

```bash
python forge_x.py --target custom --endpoint "https://api.example.com/chat" \
  --method POST --json-path "reply" --headers '{"Authorization":"Bearer TOKEN"}' \
  --language auto --analysis-mode strict --audit --rounds 20 \
  --workers 2 --rate-limit 1 --format html --output reports/final.html \
  --offline --authorized
```

## GraphQL target

```bash
python forge_x.py --target graphql --endpoint "https://api.example.com/graphql" \
  --category graphql --language auto --analysis-mode strict --rounds 20 \
  --workers 2 --rate-limit 1 --format html --output reports/graphql.html \
  --offline --authorized
```

## WebSocket target

```bash
python forge_x.py --target custom --method WS --endpoint "wss://chat.example.com/ws" \
  --language auto --analysis-mode strict --rounds 15 --workers 1 \
  --rate-limit 1 --format html --output reports/ws.html --offline --authorized
```

## Analyzer modes

- `strict`: final report mode. Lowest false-positive risk.
- `balanced`: default mode. Good for normal testing.
- `sensitive`: discovery mode. Review results manually before reporting.
