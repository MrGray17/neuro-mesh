import asyncio
import websockets
import json

# Thread-safe set of connected React UI clients
connected_clients = set()

async def register_client(websocket):
    """Registers a new React dashboard connection."""
    connected_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.remove(websocket)

class TelemetryReceiver(asyncio.DatagramProtocol):
    """Listens for high-speed UDP packets from the C++ agent."""
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = data.decode('utf-8')
        # If we have connected UI clients, push the telemetry to them
        if connected_clients:
            asyncio.create_task(self.broadcast(message))

    async def broadcast(self, message):
        """Fan-out the JSON log to all WebSockets."""
        # websockets.broadcast is optimized for concurrent fan-out
        websockets.broadcast(connected_clients, message)

async def main():
    print("🚀 Neuro-Mesh Bridge API Online.")
    
    # 1. Start WebSocket server for React (Port 8080)
    async with websockets.serve(register_client, "localhost", 8080):
        print("📡 WebSocket Server listening on ws://localhost:8080")
        
        # 2. Start UDP listener for C++ agent (Port 50052)
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: TelemetryReceiver(),
            local_addr=('127.0.0.1', 50052)
        )
        print("🔌 Internal UDP Listener bound to 127.0.0.1:50052")
        
        # Keep the event loop alive forever
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Shutting down Bridge API]")
