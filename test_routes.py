import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), 'TrustVault'))
from app import app

with app.test_client() as client:
    for route in ['/owner','/viewer','/admin']:
        resp = client.get(route, follow_redirects=False)
        print(route, resp.status_code)
