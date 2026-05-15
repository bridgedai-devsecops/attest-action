# BridgedAI Attest (`bridgedai-devsecops/attest-action`)

## What this action does

Creates in-toto **Statement v1** JSON and a portable **DSSE envelope** wrapper on disk, with conservative behavior for signing/Rekor integration.

## Why BridgedAI exists

Attestations connect artifacts to policy, provenance, and vulnerability evidence.

## Quick start

See `examples/basic.yml`.

## Enterprise setup

Plan key management (`cosign`, KMS/HSM) and GitHub artifact attestations separately; this action fails closed when required tooling/policy is missing.

## Inputs / outputs

See `action.yml`.

## Required permissions

`contents: read` for create-only paths; signing workflows may require additional permissions.

## Support

Use your BridgedAI support channel.

