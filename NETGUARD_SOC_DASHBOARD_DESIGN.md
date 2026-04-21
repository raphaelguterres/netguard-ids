# NetGuard SOC Dashboard Design

## Design Objective
Build a CrowdStrike-inspired SOC experience for NetGuard that feels:

- precise
- credible
- calm under pressure
- fast to scan
- ready for SaaS multi-tenant operation

This dashboard should communicate:

- control
- endpoint visibility
- security maturity
- operational confidence

## Design Direction
NetGuard should use a dark, disciplined command-center look with:

- deep graphite backgrounds
- restrained electric-cyan primary accent
- warm severity accents for urgency
- compact cards and dense data surfaces
- minimal ornamentation

Reference character:

- CrowdStrike Falcon for posture and clarity
- Microsoft Defender for operational grouping
- fintech polish in spacing, contrast, and component finish

## Information Architecture
Primary navigation:

1. Overview
2. Hosts
3. Alerts
4. Investigations
5. Timeline
6. Settings / Tenant / Integrations

Recommended initial NetGuard scope:

- Overview
- Hosts
- Host Detail
- Alerts
- Event Timeline

## UI Hierarchy
Top hierarchy:

1. global posture
2. active risk
3. host-level drilldown
4. alert queue
5. chronological evidence

Visual hierarchy rules:

- KPI cards first
- critical and high alerts always above supporting telemetry
- host context pinned before raw event lists
- filters always adjacent to dense tables
- severity communicated with both color and text

## Page Structure

### 1. Overview
Purpose:

- instant posture scan in under 10 seconds

Recommended layout:

- top row: monitored hosts, active alerts, critical alerts, average risk, health, ingestion status
- middle left: severity distribution + risk posture
- middle right: recent detections stream
- bottom left: host risk summary
- bottom right: system health / ingestion pipeline / tenant health

### 2. Hosts
Purpose:

- operational inventory of monitored endpoints

Columns:

- host name
- risk score
- last seen
- active alerts
- OS
- status

Behavior:

- sortable columns
- quick filters
- click row to open host detail

### 3. Host Detail
Purpose:

- endpoint-centric investigation page

Sections:

- host hero with risk score, status, OS, last seen
- active alert strip
- timeline of events
- recent detections
- behavior anomalies
- process anomalies
- host metadata

### 4. Alerts
Purpose:

- analyst work queue

Sections:

- filter bar
- severity chips
- status controls
- dense table or list
- detail panel per alert

Each alert must show:

- title
- description
- host
- timestamp
- severity
- recommended action
- status

### 5. Event Timeline
Purpose:

- chronological incident reconstruction

Layout:

- vertical timeline rail
- grouped timestamps
- event pill by severity/type
- expandable evidence drawer

## Component Breakdown
Reusable components:

- `soc-stat-card`
- `soc-severity-chip`
- `soc-health-pill`
- `soc-panel`
- `soc-filter-bar`
- `soc-table`
- `soc-host-row`
- `soc-alert-row`
- `soc-timeline-item`
- `soc-risk-gauge`

Recommended component behavior:

- cards keep one clear meaning
- avoid nesting cards inside cards unless necessary
- tables remain dense but never cramped
- drawers are used for extra detail, not primary content

## Severity Model in UI
Use consistent severity presentation everywhere:

- `critical`: red
- `high`: orange
- `medium`: amber
- `low`: neutral slate / muted gray-blue

Severity styling rules:

- use border + background tint + text color
- never rely only on color
- pair chip with uppercase severity label

## CSS Style Direction
Core tokens:

- background: near-black graphite
- panels: slightly lifted charcoal
- borders: cool blue-gray
- accent: electric cyan / icy blue
- text primary: soft white
- text secondary: muted steel

Interaction style:

- subtle hover elevation
- mild border glow on focus
- no heavy animation
- no bouncing counters
- keep transitions under 180ms

Spacing:

- `8px` base rhythm
- 16 / 24 / 32 spacing for section rhythm
- compact dense tables

Typography:

- headings: technical, precise sans
- body: readable enterprise sans
- telemetry/meta: mono

## Suggested Icon Usage
Use simple outline icons only.

Recommended set:

- shield for overview / detections
- monitor for hosts
- bell / siren for alerts
- clock for timeline
- activity pulse for health
- network nodes for correlations
- terminal for process/script telemetry

Do not overuse icons.
Icons should support scanning, not decoration.

## Flask Template Structure Suggestion
Recommended production structure:

```text
templates/
  soc/
    base.html
    overview.html
    hosts.html
    host_detail.html
    alerts.html
    partials/
      sidebar.html
      topbar.html
      stat_card.html
      severity_chip.html
      host_table.html
      alert_table.html
      timeline_item.html
```

Static structure:

```text
static/
  soc-dashboard.css
```

## Example Layout Pattern
Recommended shell:

```text
sidebar
  -> topbar
    -> page header
      -> KPI row
        -> content grid
```

This gives:

- consistent navigation
- strong section identity
- fast mental mapping for analysts

## Integration Approach With Current NetGuard
Current state:

- `dashboard.html` is a large single-file app shell
- `static/dashboard-enterprise.css` already holds enterprise styling
- `dashboard/templates/` and Flask `templates/` already exist as lighter Jinja paths

Recommended migration path:

1. keep the current single-file dashboard operational
2. introduce a parallel Jinja scaffold for the new SOC/XDR experience
3. migrate page by page:
   - overview
   - hosts
   - alerts
   - host detail
4. move reusable styling into `static/soc-dashboard.css`
5. progressively split existing JS by page responsibility

This avoids a risky full rewrite and keeps SaaS evolution realistic.

## Product Notes
For SMB EDR/XDR, the dashboard should optimize for:

- confidence over novelty
- clean drilldown over flashy graphics
- evidence clarity over widget count
- host-centric investigations over generic SOC vanity charts
