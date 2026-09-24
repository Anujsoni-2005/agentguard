from fastapi import FastAPI, Request
import base64
import time

app = FastAPI()

received_requests = []

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def catch_all(request: Request, path: str):
    if path == "__received":
        return received_requests
    if path == "__reset" and request.method == "POST":
        received_requests.clear()
        return {"status": "ok"}
        
    body = await request.body()
    received_requests.append({
        "ts": time.time(),
        "method": request.method,
        "path": "/" + path,
        "headers": dict(request.headers),
        "body_b64": base64.b64encode(body).decode('utf-8')
    })
    
    return {"status": "ok"}
