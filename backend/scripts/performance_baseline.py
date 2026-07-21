import time
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from app.core.config import settings

async def measure_queries():
    """Measure query performance before/after index creation"""
    print(f"Connecting to {settings.DATABASE_URL.split('@')[-1]}...")
    engine = create_async_engine(settings.DATABASE_URL)
    
    queries = {
        "latest_evidence": "SELECT * FROM evidence_entries WHERE control_id = 'AC-001' ORDER BY collected_at DESC LIMIT 1",
        "risk_history": "SELECT * FROM risk_scores WHERE risk_id = 1 ORDER BY recorded_at DESC LIMIT 50",
        "latest_control_results": "SELECT DISTINCT ON (control_id) * FROM control_results ORDER BY control_id, executed_at DESC",
    }
    
    print("\nStarting performance measurement (100 iterations each)...\n")
    
    for name, query in queries.items():
        times = []
        try:
            async with engine.connect() as conn:
                for _ in range(100):
                    start = time.time()
                    await conn.execute(query)
                    times.append(time.time() - start)
            
            avg = sum(times) / len(times)
            p99 = sorted(times)[99]
            print(f"✅ {name.ljust(25)}: avg={avg*1000:.2f}ms \t p99={p99*1000:.2f}ms")
        except Exception as e:
            print(f"❌ {name.ljust(25)}: FAILED ({str(e)})")

    await engine.dispose()
    print("\nMeasurement complete.")

if __name__ == "__main__":
    asyncio.run(measure_queries())
