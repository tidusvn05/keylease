# Running a program with vault secrets

Step 7 of [ADR 0005](adr/0005-agent-trust-and-secret-use.md), tier T3. Use it
for CLIs that only read credentials from the environment and have no broker
([SSH](ssh-agent.md), [PostgreSQL](db-proxy.md) or a connector).

```sh
keylease run --env STRIPE_API_KEY=kl://VAULT_ID/ITEM_ID/password \
             --env AWS_SECRET_ACCESS_KEY=ITEM_ID/secret_key \
             -- terraform plan
```

- One approval per run covers every `--env` of the same item. It shows the
  program's name and the field keys, and it is `entry:inject_secret`, risk R4,
  so it can never be trusted for a window: the program receives the value
  and could print it in an encoded form.
- The values are set only in the child's environment. Its stdout and stderr
  are scrubbed of each value, its base64 form and its percent-encoded form,
  replaced by `[REDACTED by keylease]`, including matches that span reads.
  Values shorter than 4 characters are not scrubbed.
- The child's exit code is passed through; stdin is inherited.

Scrubbing prevents accidental disclosure into an agent's transcript. It is not
a boundary against a program, or an agent, that wants the value: prefer a
broker whenever one exists.
