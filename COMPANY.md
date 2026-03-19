# Maximlabs: Company Overview

**Website:** [maximlabs.co](https://maximlabs.co)  
**Founded:** 2026  
**Stage:** Pre-launch MVP, active open-source community building  
**Sector:** AI Infrastructure / Security  

Maximlabs is building the foundational security layer that makes autonomous AI agents safe to run on local and corporate machines. Our flagship open-source product, Mercer, is a zero-trust execution environment for the agentic era.

## The Market Opportunity

The industry recognizes that autonomous coding agents are a massive security liability. Enterprise adoption of local agentic workflows is currently blocked by InfoSec teams who refuse to allow un-sandboxed agents on corporate hardware. 

Mercer is the pick-and-shovel infrastructure for the autonomous agent gold rush. We are not competing to build the smartest agent; we are building the foundational guardrails that allow *every* agent to be safely deployed.

## Competitive Positioning

| Solution Type | Examples | Native Dev Experience? | Resource Cost | OS-Level Enforcement? |
| --- | --- | --- | --- | --- |
| **MicroVMs** | EctoLedger, Boxlite | No (Forced isolation) | Heavy | No (Trapped in VM) |
| **Enterprise EDRs** | CrowdStrike, Defender | No (Bloated background) | Heavy | Yes |
| **Python/Framework Limits** | LangChain tools | Yes | Light | No (Easily bypassed) |
| **Mercer** | — | Yes (Seamless wrapper) | Ultra-light (Rust) | Yes (Kernel APIs) |

## Business Model

Our go-to-market strategy relies on a "Trojan Horse" open-source model, driving viral developer adoption to fuel B2B enterprise sales.

| Tier | Price | Offering |
| --- | --- | --- |
| **Community** | Free / Open Source | The core CLI tool. Perfect for solo developers. Builds viral adoption and establishes the industry standard. |
| **Mercer Pro** | $15–$49 / user / month | Hosted SaaS telemetry dashboard. Engineering teams can view and manage intercepted syscalls, policy violations, and agent activity across all their developers' machines. |
| **Enterprise** | Custom Contracts | Embedded SDK licenses for companies building commercial agent platforms who require native security baked into their runtimes. |

## Engineering Stack

We prioritize high-performance, low-level execution over bloated cloud infrastructure.

| Component | Technology | 
| --- | --- | 
| **Core Engine** | Rust (Memory-safe, highly concurrent) | 
| **Linux Adapter** | Linux Landlock API | 
| **macOS Adapter** | Endpoint Security API (via `endpoint-sec` crate) |
| **Telemetry DB** | SQLite (Local storage) | 
| **Dashboard** | Next.js + Tailwind (Terminal-inspired UI) |
| **Distribution** | Single Static Binary | 

**Hosting Profile:** $0 core infrastructure cost. The engine runs entirely on the end-user's local machine.

## Company Operations

Maximlabs is an **agent-operated company**. The majority of day-to-day operations are handled autonomously by an internal agent swarm. Every internal agent runs safely within Mercer sandboxes, proving the product in production daily.

| Agent | Role |
| --- | --- |
| **Dev Agent** | Monitors GitHub, implements features, manages deployments. |
| **Support Agent** | 24/7 Discord, Slack, and email technical support. |
| **Growth Agent** | Lead scraping, outreach drafting, and qualification. |
| **Ops Agent** | Real-time cost monitoring and invoicing. |
| **Content Agent** | Updates maximlabs.co and generates technical marketing content. |

**Monthly operational cost:** Under $50.

## Leadership

**Basel** — Founder, Maximlabs  
Based in Amman, Jordan.  
Building at high velocity with AI-augmented operational structures.