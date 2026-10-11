"""Small ASGI reverse proxy for opt-in localhost access to Streamlit."""

import logging

import httpx
import websockets
from starlette.applications import Starlette
from starlette.responses import StreamingResponse
from starlette.routing import Route, WebSocketRoute

UPSTREAM = "http://console:8501"
WS_UPSTREAM = "ws://console:8501"
logger = logging.getLogger(__name__)
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade"}


async def proxy_http(request):
    url = f"{UPSTREAM}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in HOP_BY_HOP and k.lower() != "host"}
    client = httpx.AsyncClient(timeout=None)
    upstream = await client.send(client.build_request(
        request.method, url, headers=headers, content=await request.body()), stream=True)
    response_headers = {k: v for k, v in upstream.headers.items()
                        if k.lower() not in HOP_BY_HOP}

    async def stream():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    return StreamingResponse(stream(), status_code=upstream.status_code,
                             headers=response_headers)


async def proxy_websocket(browser):
    uri = f"{WS_UPSTREAM}{browser.url.path}"
    if browser.url.query:
        uri += f"?{browser.url.query}"
    try:
        # This connection is to another container on the Compose network. The
        # websockets library honors HTTP_PROXY/WS_PROXY environment variables
        # by default; routing an internal Docker hostname through a host proxy
        # breaks Streamlit's browser session when Docker Desktop injects proxy
        # settings into containers.
        async with websockets.connect(
            uri,
            origin=browser.headers.get("origin"),
            proxy=None,
            # Streamlit can send large upload/session events over its
            # WebSocket. The library default is 1 MiB, which closed the
            # console connection for a ~1.2 MiB frame and cleared the UI.
            # Keep a finite ceiling while allowing larger demo documents.
            max_size=32 * 1024 * 1024,
        ) as upstream:
            logger.info("Streamlit upstream WebSocket connected for %s", uri)
            # Select one offered protocol. Echoing the raw header can contain
            # multiple comma-separated values and produces an invalid
            # Sec-WebSocket-Protocol response; omitting selection is rejected
            # by Streamlit's browser client, which requires negotiation.
            offered_protocols = browser.scope.get("subprotocols", [])
            selected_protocol = offered_protocols[0] if offered_protocols else None
            logger.info("Browser offered WebSocket subprotocols: %r", offered_protocols)
            await browser.accept(subprotocol=selected_protocol)

            async def browser_to_upstream():
                while True:
                    message = await browser.receive()
                    if message["type"] == "websocket.disconnect":
                        logger.info(
                            "Browser WebSocket disconnected: code=%s reason=%r",
                            message.get("code"), message.get("reason"),
                        )
                        break
                    payload = message.get("text")
                    if payload is None:
                        payload = message.get("bytes", b"")
                    await upstream.send(payload)

            async def upstream_to_browser():
                try:
                    async for message in upstream:
                        if isinstance(message, bytes):
                            await browser.send_bytes(message)
                        else:
                            await browser.send_text(message)
                finally:
                    logger.info(
                        "Streamlit upstream WebSocket ended: code=%s reason=%r",
                        upstream.close_code, upstream.close_reason,
                    )

            import asyncio
            tasks = [asyncio.create_task(browser_to_upstream()),
                     asyncio.create_task(upstream_to_browser())]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
    except Exception:
        logger.exception("Streamlit upstream WebSocket failed for %s", uri)
        try:
            await browser.close(code=1011)
        except RuntimeError:
            # The browser may already have closed its side of the connection.
            pass


app = Starlette(routes=[
    Route("/{path:path}", proxy_http, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
    WebSocketRoute("/{path:path}", proxy_websocket),
])
