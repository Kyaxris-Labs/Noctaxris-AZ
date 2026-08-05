<!-- Short description (max 100 chars):
Run Azure-shaped security labs without a cloud bill or a host Docker socket.
-->

<p align="center">
  <img src="https://raw.githubusercontent.com/Kyaxris-Labs/Noctaxris-AZ/main/assets/noctaxris_az_bg.png" alt="Noctaxris-AZ" width="640">
</p>

<p align="center">
  <b>Run Azure-shaped security labs on your laptop without a cloud bill or a host Docker socket.</b>
</p>

```bash
docker pull kyaxris/noctaxris-az:latest
# Generate unique roots (shipped example pair is refused).
ROOT_ID="$(openssl rand -hex 16)"
ROOT_TOKEN="$(openssl rand -hex 32)"
docker run -d --name noctaxris-az -p 127.0.0.1:4599:4599 -p 127.0.0.1:5672:5672 \
  -e NOCTAXRIS_AZ_LISTEN=0.0.0.0:4599 \
  -e NOCTAXRIS_AZ_AMQP_LISTEN=0.0.0.0:5672 \
  -e NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN=1 \
  -e NOCTAXRIS_AZ_ROOT_CLIENT_ID="$ROOT_ID" \
  -e NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN="$ROOT_TOKEN" \
  kyaxris/noctaxris-az:latest
curl http://127.0.0.1:4599/_noctaxris-az/health
```

Point Azure clients at `http://127.0.0.1:4599` with `Authorization: Bearer <token>` (Storage Shared Key / SAS; Service Bus AMQP on `:5672`). Tags: `latest`, semver, `nightly`.

Full service matrix and docs: [github.com/Kyaxris-Labs/Noctaxris-AZ](https://github.com/Kyaxris-Labs/Noctaxris-AZ).

License: [MIT](https://github.com/Kyaxris-Labs/Noctaxris-AZ/blob/main/LICENSE)
