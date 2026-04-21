import requests
from engine.attack_timeline import AttackTimelineEngine

NETGUARD_API = "http://127.0.0.1:5000"
TOKEN = input("Cole seu token do NetGuard: ").strip()

engine = AttackTimelineEngine()

resp = requests.get(
    f"{NETGUARD_API}/api/soc/events?limit=100",
    headers={"Authorization": f"Bearer {TOKEN}"},
    timeout=10,
)

resp.raise_for_status()
data = resp.json()

events = data.get("events", [])
timelines = engine.build_timelines(events)

for timeline in timelines:
    print("=" * 60)
    print(f"Attack ID:  {timeline.attack_id}")
    print(f"Host:       {timeline.host_id}")
    print(f"Risk Score: {timeline.risk_score}")
    print("-" * 60)

    for step in timeline.steps:
        print(f"[{step.timestamp}] {step.phase} - {step.event_type} ({step.severity})")
        print(f"  {step.message}")