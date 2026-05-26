# CyberWall XDR Architecture Documentation

This document describes the high-level design of the CyberWall XDR SOC dashboard and IDS/IPS engine.

## Microservices Design

The XDR system is built out of 5 primary containerized elements:

```
                  ┌──────────────────────┐
                  │  React.js Frontend   │ (Port 3000/Nginx build)
                  └──────────┬───────────┘
                             │ (HTTPS/WebSockets)
                             ▼
                  ┌──────────────────────┐
                  │ Nginx Reverse Proxy  │ (Port 80 Router)
                  └──────────┬───────────┘
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
┌──────────────────────┐           ┌──────────────────────┐
│  Node.js API Server  │           │   Python IDS/IPS     │ (Scapy sniffer,
└──────────┬───────────┘           └──────────┬───────────┘  detectors, iptables)
           │ (Mongoose)                       │
           ▼                                  │ (REST Telemetry & WebSockets)
┌──────────────────────┐                      │
│     MongoDB Store    │ ◄────────────────────┘
└──────────────────────┘
```

### Component Breakdown

1. **Nginx Proxy**: Routes requests to the static SPA resources or forwards `/api` endpoints and `/socket.io` websocket upgrades to the backend server.
2. **React SOC Frontend**: Interactive real-time operations dashboard built using Vite, Framer Motion, and Recharts. Connects to backend via Socket.IO Client.
3. **Node.js Express Backend**: The API controller. Persists alerts, logs raw traffic statistics, exposes JWT token verification, and acts as the Socket.IO event broadcaster.
4. **Python IDS/IPS Engine**: Uses Scapy to sniff raw NIC sockets, passes headers through threat-detection logic, triggers blocks, and publishes alerts via WebSocket client and REST requests.
5. **MongoDB**: Secure data warehouse storing incidents history, active block lists, user credentials, and network logs.
