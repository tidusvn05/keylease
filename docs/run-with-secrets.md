# Running a program with vault secrets

Step 7 of [ADR 0005](adr/0005-agent-trust-and-secret-use.md), tier T3. Use it
for CLIs that only read credentials from the environment and have no broker
([SSH](ssh-agent.md), [PostgreSQL](db-proxy.md) or a connector).

```sh
keylease run --env STRIPE_API_KEY=kl://VAULT_ID/ITEM_ID/password \
             --env AWS_SECRET_ACCESS_KEY=ITEM_ID/secret_key \
             -- terraform plan
```

References can also name the item, which is easier to write and to read in
an approval: `kl://PROJECT[/ENVIRONMENT]/ITEM#FIELD`, with the item's title
(case-insensitive) and the field's key, label or `.env` variable name.

```sh
keylease run --env STRIPE_API_KEY=kl://shop/production/Stripe#password -- ./deploy.sh
```

`--project shop --environment production` sets every variable of the
project's env files (`core.environment` items) in that environment, without
listing them; `--env` bindings add to or override them:

```sh
keylease run --project shop --environment production -- npm run migrate
```

See [projects and environments](projects-and-environments.md).

- One approval per run covers every `--env` of the same item. It shows the
  program's name and the field keys, and it is `entry:inject_secret`, risk R3:
  approve it once, or trust it for up to an hour (on the item, or with its
  project) so repeated deploys and test runs do not ask each time. During that
  hour the agent may run any program with the value, and a program can print
  it in an encoded form; trust only an agent you would let run commands.
- The values are set only in the child's environment. Its stdout and stderr
  are scrubbed of each value, its base64 form and its percent-encoded form,
  replaced by `[REDACTED by keylease]`, including matches that span reads.
  Values shorter than 4 characters are not scrubbed.
- The child's exit code is passed through; stdin is inherited.

The program name in the approval is what the agent says it will run. KeyLease
does not verify it: treat the approval exactly like a reveal.

Scrubbing prevents accidental disclosure into an agent's transcript. It is not
a boundary against a program, or an agent, that wants the value: prefer a
broker whenever one exists.
