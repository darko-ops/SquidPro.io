import os, time, math, random
from fastapi import FastAPI, Query

SEED = int(os.getenv("SEED", "42"))
random.seed(SEED)

api = FastAPI(title="Collector Crypto (Demo)", version="0.1.0")

@api.get("/price")
def price(pair: str = Query("BTCUSDT")):
    # Demo-only price generator (sine wave + noise)
    t = time.time()
    base = 60000 + 1000 * math.sin(t / 300.0)
    price = round(base + random.uniform(-50, 50), 2)
    volume = round(abs(math.sin(t / 60.0)) * 200 + random.uniform(0, 50), 2)
    return {"pair": pair, "price": price, "volume": volume, "ts": int(t)}
