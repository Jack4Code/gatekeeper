```markdown
# Fly.io Deployment

## Local Development

To develop locally against the Fly Postgres database:

```bash
flyctl proxy 5432 -a jg-gatekeeper-db
```

Keep that terminal open. Your app connects to `localhost:5432` with `?sslmode=disable`.

## Deploying

### First-time setup

1. Create the Postgres database:
```bash
flyctl postgres create
```
Choose Development config, enable scale-to-zero if you want free tier.

2. Create the app:
```bash
flyctl apps create jg-gatekeeper
```

3. Set secrets:
```bash
flyctl secrets set DATABASE_URL="postgres://USER:PASS@DB_NAME.internal:5432/postgres?sslmode=disable" JWT_SECRET="your-secret"
```

4. Deploy:
```bash
flyctl deploy
```

### Subsequent deploys

```bash
flyctl deploy
```

## Useful commands

```bash
flyctl status -a jg-gatekeeper      # app status
flyctl logs -a jg-gatekeeper        # app logs
flyctl status -a jg-gatekeeper-db   # db status
flyctl machine start <id> -a jg-gatekeeper-db  # wake up db if scaled to zero
```
```