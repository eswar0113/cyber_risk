import json
from dotenv import load_dotenv
load_dotenv()

from scanners.risk_scoring import getScore

# Run scan and auto-save to PostgreSQL (save_to_db=True is the default)
result = getScore("demo.testfire.net")
print(json.dumps(result, indent=2, default=str))