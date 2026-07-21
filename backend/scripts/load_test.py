"""
SENTINEL-GRC Locust Load Test

Simulates concurrent user traffic to measure the impact of recent performance
fixes (N+1 removal, indexing, pagination, and Celery offloading).

Usage:
  locust -f scripts/load_test.py -u 100 -r 10 -t 5m http://localhost:8000
"""

from locust import HttpUser, task, between

class SentinelGRCUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        """Simulate user login"""
        # In a real test, you'd acquire a JWT here.
        # For now, we assume the test runs against a mock-auth endpoint or with a valid token
        self.headers = {"Authorization": "Bearer TEST_TOKEN"}

    @task(3)
    def view_dashboard(self):
        """Simulate loading the main dashboard"""
        self.client.get("/api/v1/controls/", headers=self.headers)
        self.client.get("/api/v1/risks/?limit=10", headers=self.headers)

    @task(2)
    def scroll_risks(self):
        """Simulate scrolling through the risk register using cursor pagination"""
        response = self.client.get("/api/v1/risks/?limit=50", headers=self.headers)
        if response.status_code == 200:
            data = response.json()
            next_cursor = data.get("next_cursor")
            if next_cursor:
                self.client.get(f"/api/v1/risks/?cursor={next_cursor}&limit=50", headers=self.headers)

    @task(1)
    def view_risk_detail(self):
        """Simulate viewing a specific risk and its history chart"""
        self.client.get("/api/v1/risks/1", headers=self.headers)
        
    @task(1)
    def verify_evidence(self):
        """Simulate verifying an evidence chain"""
        self.client.get("/api/v1/evidence/", headers=self.headers)
