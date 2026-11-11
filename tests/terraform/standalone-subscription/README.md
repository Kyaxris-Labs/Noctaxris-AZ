# Standalone subscription

Set `NOCTAXRIS_AZ_LAB_STANDALONE=1`, then `POST /_noctaxris-az/lab/subscriptions:seedStandalone` with the root bearer. Set `subscription_id` to the returned `subscriptionId` and the access token to the returned `accessToken` before an operator apply.

`tests/terraform/run.sh` only runs `terraform init` and `terraform validate`. It does not apply.
