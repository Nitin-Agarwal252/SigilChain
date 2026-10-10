"""Same-origin loopback reverse proxy, including Streamlit WebSockets."""
from __future__ import annotations

import asyncio

import httpx
import websockets
from starlette.applications import Starlette
from starlette.responses import StreamingResponse
from starlette.routing import Route, WebSocketRoute

UPSTREAM = "http://console:8501"
WS_UPSTREAM = "ws://console:8501"
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
       "trailers", "transfer-encoding", "upgrade"}


async def proxy_http(request):
    url = UPSTREAM + request.url.path + (("?" + request.url.query) if request.url.query else "")
    headers = {key: value for key, value in request.headers.items()
               if key.lower() not in HOP | {"host", "content-length"}}
    client = httpx.AsyncClient(timeout=None, trust_env=False)
    upstream = await client.send(client.build_request(request.method, url,
        headers=headers, content=await request.body()), stream=True)
    response_headers = {key: value for key, value in upstream.headers.items() if key.lower() not in HOP}

    async def body():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    return StreamingResponse(body(), status_code=upstream.status_code, headers=response_headers)


async def proxy_websocket(browser):
    uri = WS_UPSTREAM + browser.url.path + (("?" + browser.url.query) if browser.url.query else "")
    try:
        async with websockets.connect(uri, origin=browser.headers.get("origin"), proxy=None) as upstream:
            protocols = browser.scope.get("subprotocols", [])
            await browser.accept(subprotocol=protocols[0] if protocols else None)

            async def from_browser():
                while True:
                    message = await browser.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    await upstream.send(message.get("text") if message.get("text") is not None else message.get("bytes", b""))

            async def to_browser():
                async for message in upstream:
                    if isinstance(message, bytes):
                        await browser.send_bytes(message)
                    else:
                        await browser.send_text(message)

            tasks = [asyncio.create_task(from_browser()), asyncio.create_task(to_browser())]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
    except Exception:
        await browser.close(code=1011)


app = Starlette(routes=[Route("/{path:path}", proxy_http,
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
    WebSocketRoute("/{path:path}", proxy_websocket)])
