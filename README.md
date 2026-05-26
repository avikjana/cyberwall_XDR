# CyberWall XDR - Real-Time SOC & IPS Platform

CyberWall XDR is a production-grade cybersecurity platform featuring real-time packet monitoring, threat detection, auto-blocking firewall integration, and a modern Security Operations Center (SOC) dashboard.

## 🚀 Key Features
- **Real-Time Sniffing**: Uses Python Scapy to intercept and parse headers.
- **IDS/IPS Rules**: Signatures for Port Scanning, SYN flooding, and DNS Anomaly detection.
- **Auto Blocking**: Dynamically applies Linux `iptables` rules to drop attacker traffic.
- **WebSockets Alerts**: Instant live alerts broadcasted to the React glassmorphic dashboard.
- **Incident Response**: Admins can manually add/remove IP blocklist records.

---

## 🛠️ Tech Stack
- **Frontend**: React (Vite), Tailwind CSS, Framer Motion, Recharts, Lucide Icons, Socket.IO Client.
- **Backend**: Node.js, Express, Socket.IO, JWT, Helmet.js, Mongoose.
- **Engine**: Python 3, Scapy, Requests, socketio-client.
- **DevOps**: Docker, Nginx Reverse Proxy, Docker Compose.

---

## 💻 Quick Start & Deployment

### Prerequisites
- Docker & Docker Compose installed.
- (Optional) Linux environment with `iptables` for live packet-dropping validation. On Windows, the engine falls back to simulated/dry-run logging.

### Launching the Stack
Run the following command from the root folder:

```bash
# Navigate to docker config and launch
cd docker
docker-compose up --build
```

The system will initialize all 5 containers:
1. **MongoDB**: on `localhost:27017`
2. **Backend**: on `localhost:5000`
3. **Frontend**: serving assets via Nginx
4. **Nginx Reverse Proxy**: accessible on **`http://localhost`** (Port 80)
5. **Firewall Engine**: running in host network mode

---

## 🔒 Default User Provisioning
Once the frontend is running on **`http://localhost`**, click **"Provision new analyst credentials"** to create a user and choose a role:
- **Analyst Role**: Access dashboard metrics, view threats and raw traffic logs in read-only mode.
- **Admin Role**: Full access including manual blocking/unblocking and threat acknowledgment.
