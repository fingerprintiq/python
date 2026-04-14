# fingerprintiq

[![PyPI](https://img.shields.io/pypi/v/fingerprintiq.svg)](https://pypi.org/project/fingerprintiq/)
[![Python](https://img.shields.io/pypi/pyversions/fingerprintiq.svg)](https://pypi.org/project/fingerprintiq/)
[![Downloads](https://img.shields.io/pypi/dm/fingerprintiq.svg)](https://pypi.org/project/fingerprintiq/)
[![License](https://img.shields.io/pypi/l/fingerprintiq.svg)](./LICENSE)

Official Python SDK for [FingerprintIQ](https://fingerprintiq.com) — three products in one package:

- **Identify** — server-side visitor lookup
- **Sentinel** — classify API callers as browsers, AI agents, CLI tools, or bots
- **Pulse** — CLI usage analytics and machine fingerprinting

Links: [Docs](https://docs.fingerprintiq.com) · [PyPI](https://pypi.org/project/fingerprintiq/) · [Issues](https://github.com/fingerprintiq/python/issues)

## Installation

```bash
pip install fingerprintiq              # core (Identify + Sentinel + Pulse)
pip install 'fingerprintiq[fastapi]'   # + FastAPI / Starlette middleware
```

Requires Python 3.9+.

## Identify — server-side visitor lookup

```python
from fingerprintiq import FingerprintIQ

with FingerprintIQ(api_key="fiq_live_...") as client:
    visitor = client.lookup(visitor_id="iq_abc123")
    print(visitor.visitor_id, visitor.bot_probability)
```

Async variant:

```python
import asyncio
from fingerprintiq import FingerprintIQ

async def main() -> None:
    client = FingerprintIQ(api_key="fiq_live_...")
    try:
        visitor = await client.alookup(visitor_id="iq_abc123")
        print(visitor.bot_probability)
    finally:
        await client.aclose()

asyncio.run(main())
```

## Sentinel — FastAPI middleware

```python
from fastapi import FastAPI, Request
from fingerprintiq.sentinel.fastapi import SentinelMiddleware

app = FastAPI()
app.add_middleware(SentinelMiddleware, api_key="fiq_live_...")

@app.get("/api/data")
def handler(request: Request):
    result = request.state.sentinel  # SentinelResult | None
    if result and result.caller_type == "bot":
        return {"blocked": True}
    return {"ok": True}
```

## Pulse — CLI analytics

```python
from fingerprintiq.pulse import Pulse

pulse = Pulse(api_key="fiq_live_...", tool="my-cli", version="1.2.3")
pulse.track("deploy", metadata={"duration_ms": 1234, "success": True})
pulse.shutdown()  # or let atexit handle it
```

Honors `DO_NOT_TRACK=1` and `FINGERPRINTIQ_OPTOUT=1` out of the box. Set `respect_opt_out=False` to override.

## Sibling Packages

| Package | Purpose |
|---------|---------|
| [`fingerprintiq`](https://pypi.org/project/fingerprintiq/) (PyPI) | Python SDK — Identify, Sentinel, Pulse (this package) |
| [`@fingerprintiq/js`](https://www.npmjs.com/package/@fingerprintiq/js) | Browser fingerprinting |
| [`@fingerprintiq/server`](https://www.npmjs.com/package/@fingerprintiq/server) | Server-side caller classification (Hono, Express) |
| [`@fingerprintiq/pulse`](https://www.npmjs.com/package/@fingerprintiq/pulse) | Node CLI usage analytics |

## Contributing

This repo is a **read-only public mirror**. The master copy lives in the private FingerprintIQ monorepo and is synced here on every push to `main`. Please [file issues](https://github.com/fingerprintiq/python/issues) rather than PRs.

## License

MIT
