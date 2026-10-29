# SNA Cybersecurity Investigation Platform — User & Presentation Guide

## 1. Project Overview

**Title:** Detection of Critical Hosts and Malicious Communities in Cyber Attack Networks Using Social Network Analysis  
**Academic Level:** B.Tech Computer Science Capstone Project  
**Core Technologies:**
- **Backend:** Python 3.11+, NetworkX, Pandas, Scikit-learn, FastAPI, Uvicorn
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, HeroUI v3 (`@heroui/styles`), Cytoscape.js, Plotly.js, Vite

---

## 2. Windows Setup & Execution in VS Code / Antigravity

### Prerequisites
- Python 3.11+
- Node.js v18+ (tested on Node.js v22.11.0 / npm 10.9.0)
- Git & PowerShell

### Step 1: Open Project in VS Code
Open VS Code in the project root:
```powershell
code "C:\engg notes\7th sem\SNA\SNA_Project"
```

### Step 2: Activate the Python Virtual Environment
In the VS Code terminal (PowerShell):
```powershell
# Set execution policy if script running is disabled
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Activate existing virtual environment
.\.venv\Scripts\Activate.ps1
```

*(If you ever need to reinstall Python dependencies: `pip install -r requirements.txt`)*

### Step 3: Install Frontend Dependencies
```powershell
cd frontend
npm install
cd ..
```

---

## 3. How to Launch the Application

You can run the application in two ways:

### Option A: Standard Dual-Server Mode (Recommended for Development & Live Hot-Reload)

**Terminal 1 — Start Python FastAPI Backend:**
```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.api:app --reload --host 127.0.0.1 --port 8000
```
*Backend API Docs will be available at:* `http://127.0.0.1:8000/docs`

**Terminal 2 — Start HeroUI Web Dashboard (Vite Dev Server):**
```powershell
cd frontend
npm run dev
```
*Open your browser at:* `http://127.0.0.1:5173`

---

### Option B: Single-Server Unified Mode (Fastest for Faculty Viva Demo)

The frontend is pre-built into `frontend/dist/`. FastAPI automatically mounts and serves the static production web assets!

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000
```
*Open your browser directly at:* `http://127.0.0.1:8000`  
Both the API and the full interactive HeroUI frontend run from this single command!

*(To rebuild frontend after changes: `cd frontend; npm run build; cd ..`)*

---

## 4. How to Run the Automated Test Suite

The project includes 36 automated tests covering data parsing, IP validation, graph construction, centrality, Louvain clustering, triage heuristics, and all FastAPI endpoints:

```powershell
.\.venv\Scripts\pytest -v
```

Expected output:
```
============================= 36 passed in ~15s =============================
```

---

## 5. Faculty Viva Voce Demo Script (Step-by-Step Presentation)

Follow this 5-minute presentation workflow when presenting to external examiners or professors:

### Step 1: Network Overview (`/`)
- Point out the **top metric cards**: Total flows analyzed (15,000 flows), unique hosts (nodes), directed edges, and observed attack flows.
- Explain the **Priority Breakdown Tiles**: Emphasize how `INFRASTRUCTURE_WATCH` (benign vital assets) is decoupled from `CRITICAL` (attack-associated).
- Show the **Data Sanitization Audit** table proving that RFC 1918 private subnets and IPv4 validation are handled rigorously.

### Step 2: Interactive Network Explorer
- Show the **Cytoscape.js directed graph**: Red edges represent attack flows, gray edges represent benign flows.
- Switch **"Color Nodes By"** between *Priority Tier* and *Community Cluster*.
- Switch **"Node Size By"** between *Degree*, *PageRank*, and *Betweenness*.
- Click on any node or search for an IP (e.g. `192.168.10.50`) to slide open the **Host Inspector Drawer**. Show the professor the incoming/outgoing flow volume, attack types, and natural-language topological explanation.

### Step 3: Critical Hosts Analysis
- Explain the multi-centrality ranking:
  - **In/Out Degree:** Connection fan-in/fan-out.
  - **Betweenness Centrality:** Chokepoints and lateral bridges across subnets.
  - **PageRank:** Global topological prestige.
  - **Combined Criticality:** Weighted synthesis ($w_{deg} C_{deg} + w_{bet} C_{bet} + w_{pr} PR$).
- Click on a host row to display the **Algorithmic Rationale Callout** explaining why the algorithm prioritized that specific IP.
- Click **"Export CSV"** to demonstrate real downloadable results.

### Step 4: Community Analysis & Louvain Modularity
- Show the **Louvain modularity score ($Q > 0.3$)**, indicating distinct mathematical structural clustering.
- Walk through the **Community Size vs Attack Flow Proportion chart**. Explain that Louvain identifies topological clusters, while empirical attack labels prove whether attacks concentrated within specific structural subnets.
- Select a community to inspect all member hosts.

### Step 5: Timeline Analysis
- Demonstrate temporal progression in 1-minute intervals. Show how benign baseline traffic runs continuously, while attack flows spike dramatically during the attack window.

### Step 6: Model Evaluation & Publication-Ready Figures
- Walk through the **Precision@K table** ($K \in \{5, 10, 20\}$) comparing unsupervised graph rankings against the random baseline.
- Point out **Figure 1** (Precision@K) and **Figure 2** (Community Enrichment) generated by the pipeline.

### Step 7: Reports & Exports
- Show the 5 forensic download buttons (`critical_hosts.csv`, `communities.csv`, `suspicious_hosts.csv`, `host_community_membership.csv`, `community_risk.csv`).
- Reference the **Academic Viva Defense Questions** accordion for quick theoretical definitions.

---

## 6. Key Viva Defense Questions & Answers

### Q1: What does a Node and an Edge represent?
- **Node ($v \in V$):** A unique computing host, identified by its IPv4 address (e.g., `192.168.10.50`). Internal hosts (RFC 1918 private subnets) and external internet endpoints are automatically distinguished.
- **Directed Edge ($(u, v) \in E$):** Observed communication traffic initiated from Source IP $u$ to Destination IP $v$.
- **Edge Weight ($w_{uv}$):** The total number of observed flow transmissions between host $u$ and host $v$.

### Q2: Why Louvain modularity instead of k-Means clustering?
- Network traffic is topological and relational (edges), not independent point vectors in Euclidean space.
- $k$-Means requires defining an arbitrary cluster count $k$ and calculating Euclidean centroids, which have no physical meaning in network topologies.
- Louvain optimizes the Newman-Girvan Modularity index ($Q$), which measures the density of internal links against an equivalent randomized null model, automatically detecting organic community counts.

### Q3: Why is Betweenness Centrality critical in cybersecurity?
- Betweenness measures how frequently a node falls on the shortest path between all node pairs.
- In enterprise networks, high-betweenness hosts represent **chokepoints, lateral bridges, and routers**. If compromised, attackers can pivot and intercept traffic between departments.

### Q4: Why does Centrality alone NOT mean a host is malicious?
- A DNS resolver, Active Directory domain controller, or default gateway will naturally have high degree and betweenness centrality. Flagging them as "malicious" causes catastrophic false alarms.
- Our framework classifies high-centrality benign nodes as **`INFRASTRUCTURE_WATCH`** (critical assets requiring protection), reserving **`CRITICAL`** strictly for nodes where topological importance intersects with empirical attack flows.

---

## 7. Troubleshooting Common Issues

### Issue 1: "Unable to connect to the remote server" / Port 8000 already in use
- Check if another process is using port 8000:
  ```powershell
  Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess
  ```
- Or run uvicorn on another port:
  ```powershell
  python -m uvicorn backend.api:app --port 8080
  ```

### Issue 2: PowerShell script execution blocked
- Run:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```

### Issue 3: Timestamps missing in Timeline view
- Open the header modal (**"Run / Config"**) and ensure a dataset file from `Datasets/TrafficLabelling/` (such as `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`) is selected. Anonymized `MachineLearningCVE` files do not contain timestamps.
