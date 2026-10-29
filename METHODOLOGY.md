# Research Methodology & Algorithmic Formulation

## 1. Research Problem & Objective

Traditional Network Intrusion Detection Systems (NIDS) primarily analyze individual network packets or statistical flow aggregates using rule-based signatures or vector-based machine learning classifiers. These approaches suffer from high false alarm rates, susceptibility to feature perturbation, and a complete lack of topological context.

This research formulates network traffic as a **complex relational communication graph** and utilizes **Social Network Analysis (SNA)** to:
1. Model macroscopic and microscopic communication patterns across network endpoints.
2. Uncover structural gateways, communication hubs, and authority nodes using graph centrality algorithms.
3. Partition the network into cohesive topological modules via modularity optimization.
4. Correlate topological centrality with observational attack evidence to generate explainable, evidence-aware investigation priorities.

---

## 2. Data Preparation & Ingestion Pipeline

### 2.1 Dataset Ingestion
The pipeline processes the **CIC-IDS2017** dataset. Network flow records are parsed from CSV files or ZIP archives via a streaming chunk generator (`chunksize=50000`) to guarantee a bounded memory footprint.

### 2.2 Data Sanitization Rules
For each record, the preprocessor executes:
1. **IP Sanitization & Validation:** Source and destination fields are validated using IPv4 regular expression matching (`255.255.255.255` format). Non-string, null, or malformed addresses are discarded and audited.
2. **Timestamp Normalization:** Timestamps in CIC-IDS2017 exhibit varying formats (`d/m/Y H:M` and `dd/mm/yyyy hh:mm:ss`). A mixed-format datetime parser converts records into standardized UTC datetimes while preserving temporal sequencing.
3. **Label Normalization:** Attack labels are trimmed of irregular whitespace and mapped to standardized categories (`BENIGN`, `DDoS`, `PortScan`, `Botnet`, `Infiltration`, `Web Attack`, `Brute Force`). An observational boolean flag `is_attack` is derived (`is_attack = True` if `label != 'BENIGN'`).
4. **Flow Aggregation:** Network flows sharing the identical directed endpoint pair $(u, v)$ are aggregated:
   $$w_{uv} = \sum_{f \in F_{uv}} 1$$
   $$\text{attack\_flows}_{uv} = \sum_{f \in F_{uv}} \mathbb{I}(\text{is\_attack}_f = \text{True})$$
   $$\text{attack\_ratio}_{uv} = \frac{\text{attack\_flows}_{uv}}{w_{uv}}$$

---

## 3. Graph Construction

The network is represented as a weighted, directed graph $G = (V, E, W)$:
- **Vertices ($V$):** Set of unique hosts identified by IPv4 address. Node attributes include `is_internal` (RFC 1918 classification), `sent_flows`, `received_flows`, `total_attack_flows`, and `attack_types`.
- **Directed Edges ($E$):** An ordered pair $(u, v) \in E$ indicates observed communication from source host $u$ to destination host $v$.
- **Edge Weights ($W$):** $w_{uv} \in \mathbb{Z}^+$ denotes total observed flow volume from $u$ to $v$.

For algorithms requiring undirected representations (e.g., Louvain modularity optimization), an undirected projection $G_U = (V, E_U, W_U)$ is generated where:
$$w_{U}(u, v) = w_{uv} + w_{vu}$$

---

## 4. Centrality Analysis

Centrality metrics quantify host importance from distinct structural perspectives:

### 4.1 Degree Centrality
Measures local connectivity:
- In-degree ($k_{in}(v)$): Number of distinct hosts transmitting to $v$ (fan-in / target concentration).
- Out-degree ($k_{out}(v)$): Number of distinct hosts $v$ transmits to (fan-out / scanner behavior).
- Normalized Degree Centrality:
  $$C_{deg}(v) = \frac{k_{in}(v) + k_{out}(v)}{2(|V| - 1)}$$

### 4.2 Betweenness Centrality
Quantifies the extent to which host $v$ lies on shortest communication paths between all other host pairs $(s, t)$:
$$C_B(v) = \sum_{s \neq v \neq t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$
Where $\sigma_{st}$ is the total number of shortest paths from $s$ to $t$, and $\sigma_{st}(v)$ is the number of those paths passing through $v$.
- **Large Graph Approximation:** When $|V| > 500$, Brandes randomized $k$-node sampling is utilized with $k = \min(500, \lfloor 0.2|V| \rfloor)$, reducing computational complexity from $O(|V|(|V| + |E|))$ to $O(k(|V| + |E|))$.

### 4.3 PageRank
Models topological prestige and authority via random walk with restart ($d = 0.85$):
$$PR(v) = \frac{1 - d}{|V|} + d \sum_{u \in M(v)} \frac{PR(u)}{k_{out}(u)}$$
Where $M(v)$ is the set of hosts with directed edges into $v$.

### 4.4 Normalized Combined Criticality
To synthesize multi-dimensional centrality into a single structural score, individual metrics are min-max normalized to $[0, 1]$:
$$C'_{m}(v) = \frac{C_m(v) - \min(C_m)}{\max(C_m) - \min(C_m) + \epsilon}$$
The combined structural criticality is computed as:
$$\text{Criticality}(v) = w_{deg} \cdot C'_{deg}(v) + w_{bet} \cdot C'_{B}(v) + w_{pr} \cdot PR'(v)$$
Subject to $w_{deg} + w_{bet} + w_{pr} = 1.0$ (default configuration: $0.35, 0.35, 0.30$).

---

## 5. Community Detection

Community detection identifies structural clusters where internal edge density exceeds external link density.

### 5.1 Louvain Algorithm
The Louvain algorithm optimizes the **Newman-Girvan Modularity ($Q$)** on the weighted undirected projection $G_U$:
$$Q = \frac{1}{2m} \sum_{i,j} \left[ A_{ij} - \gamma \frac{k_i k_j}{2m} \right] \delta(c_i, c_j)$$
Where:
- $A_{ij}$ is the edge weight between hosts $i$ and $j$.
- $k_i = \sum_j A_{ij}$ is the weighted degree of host $i$.
- $m = \frac{1}{2} \sum_{ij} A_{ij}$ is the total network weight.
- $c_i$ is the community assignment of host $i$.
- $\delta(c_i, c_j) = 1$ if $c_i = c_j$, and 0 otherwise.
- $\gamma$ is the resolution parameter (default $\gamma = 1.0$).

### 5.2 Community Characterization Metrics
For each community $C \subset V$:
- **Internal Density:** $\rho(C) = \frac{2 \cdot |E_{int}|}{|C|(|C| - 1)}$ for $|C| > 1$.
- **Conductance:** $\phi(C) = \frac{\text{Vol}_{ext}(C)}{\text{Vol}_{int}(C) + \text{Vol}_{ext}(C)}$, measuring structural isolation.
- **Empirical Attack Proportion:** $\alpha(C) = \frac{\text{AttackFlows}(C)}{\text{TotalFlows}(C)}$, measuring observational attack concentration.

---

## 6. Explainable Evidence-Aware Prioritization

A critical flaw in naive graph-based cybersecurity is assuming that central nodes are malicious. High-centrality nodes are frequently vital infrastructure (e.g., DNS servers, domain controllers, default gateways).

To eliminate false positives, the system strictly isolates structural criticality ($S_{struct}$) from empirical attack evidence ($E_{attack}$):

### 6.1 Formulations
1. **Structural Criticality ($S_{struct} \in [0, 1]$):** Computed purely from graph topology via combined criticality.
2. **Observed Attack Evidence ($E_{attack} \in [0, 1]$):**
   $$E_{attack}(v) = 0.6 \cdot \left(\frac{\text{AttackFlows}(v)}{\text{TotalFlows}(v)}\right) + 0.4 \cdot \left(\frac{\ln(1 + \text{AttackFlows}(v))}{\max_u \ln(1 + \text{AttackFlows}(u))}\right)$$
3. **Community Risk ($C_{risk} \in [0, 1]$):** Attack flow ratio of host $v$'s assigned community.
4. **Investigation Priority Score:**
   $$\text{Priority}(v) = 0.50 \cdot E_{attack}(v) + 0.30 \cdot S_{struct}(v) + 0.20 \cdot C_{risk}(v)$$

### 6.2 Action Tiers & Automated Explanations
| Tier | Criteria | Operational Semantic |
| :--- | :--- | :--- |
| **`CRITICAL`** | $E_{attack} > 0.4$ and $S_{struct} > 0.3$ | Active threat or key victim at critical topological chokepoint. |
| **`HIGH`** | $E_{attack} > 0.1$ or $\text{Priority} \ge 0.45$ | Significant attack involvement or member of malicious cluster. |
| **`INFRASTRUCTURE_WATCH`** | $S_{struct} \ge 0.5$ and $E_{attack} = 0$ | **Critical benign infrastructure.** Defensively monitor and protect; NOT a malicious host. |
| **`MEDIUM`** | $E_{attack} > 0$ or $\text{Priority} \ge 0.20$ | Peripheral host with limited observed attack activity. |
| **`LOW`** | $\text{Priority} < 0.20$ | Routine baseline traffic with zero attack indicators. |

---

## 7. Empirical Evaluation & Research Validation

### 7.1 Prevention of Data Leakage
To evaluate whether graph structure possesses predictive or diagnostic utility:
1. Centrality metrics are computed **strictly unsupervised** without exposure to attack labels.
2. An observational host proxy label ($y_v \in \{0, 1\}$) is defined:
   $$y_v = \mathbb{I}(\text{total\_attack\_flows}(v) > 0)$$
3. Precision@K evaluates whether the top-$K$ hosts ranked by unsupervised centrality identify attack-involved hosts more effectively than random chance:
   $$\text{Precision@}K = \frac{1}{K} \sum_{i=1}^K y_{\pi(i)}$$
   Where $\pi$ is the ranking induced by each centrality metric.
4. **Temporal Split Validation:** Centrality is calculated over an early time window $T_1$, and evaluated against attacks emerging in subsequent window $T_2$, proving structural predictive utility without temporal leakage.

---

## 8. Limitations & Future Work

1. **Host Proxy Labels:** Flow-level labels serve as observational proxies for host involvement; host endpoint telemetry (e.g., EDR logs, process trees) is required for definitive forensic proof of compromise.
2. **Encrypted Payloads:** The analysis operates on network flow metadata (IPs, ports, protocols, flow volumes) and does not inspect packet payloads.
3. **Dynamic Topology:** Time-windowed static graphs capture temporal evolution in discrete slices; future extensions can explore continuous-time dynamic graph neural networks (DGNNs).
