import asyncio
import websockets
import json
import psutil
import time
import ssl
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

API_KEY = "Api-Key From Dashboard"
SERVER_NAME = "MyServer01"
WS_SERVER_URL = "wss://localhost/dashboard/ws"

# Create an SSL context with TLS 1.3
ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def get_system_metrics() -> Dict[str, Any]:
    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "uptime": int(time.time() - psutil.boot_time())
    }

async def send_metrics():
    headers = {
        "x-api-key": API_KEY,
        "x-server-name": SERVER_NAME
    }
    
    reconnect_delay = 5
    max_reconnect_delay = 60
    
    while True:
        try:
            async with websockets.connect(
                WS_SERVER_URL,
                extra_headers=headers,
                ssl=ssl_context
            ) as websocket:
                logging.info(f"Connected to {WS_SERVER_URL}")
                reconnect_delay = 5  # Reset delay on successful connection
                
                while True:
                    try:
                        metrics = get_system_metrics()
                        message = {
                            "type": "metrics",
                            "data": metrics
                        }
                        await websocket.send(json.dumps(message))
                        logging.debug(f"Sent metrics: {metrics}")
                        
                        response = await asyncio.wait_for(websocket.recv(), timeout=10)
                        response_data = json.loads(response)
                        
                        if "error" in response_data:
                            logging.warning(f"Server reported error: {response_data['error']}")
                        
                        await asyncio.sleep(2)  # Regular metrics interval
                        
                    except asyncio.TimeoutError:
                        logging.warning("Server response timeout")
                        break
                    except json.JSONDecodeError:
                        logging.error(f"Invalid JSON in server response: {response}")
                        continue
                        
        except websockets.exceptions.ConnectionClosed as e:
            logging.warning(f"Connection closed: {e}. Retrying in {reconnect_delay} seconds...")
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)
            
        except Exception as e:
            logging.error(f"Unexpected error: {e}. Retrying in {reconnect_delay} seconds...")
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)

if __name__ == "__main__":
    try:
        asyncio.run(send_metrics())
    except KeyboardInterrupt:
        logging.info("Stopped by user")