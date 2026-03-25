import json
from db.db import get_all_scans, get_scan_by_id

scans = get_all_scans()
print(f"=== DB VERIFICATION ===")
print(f"Total Scans Found: {len(scans)}\n")

for s in scans:
    print(f"- Session ID: {s['id']} | Target: {s['target']} | Composite Score: {s['composite_score']} | Time: {s['scan_time']}")

print("\n\n=== Latest Scan Details (ID 1) ===")
print(json.dumps(get_scan_by_id(1), indent=2))
