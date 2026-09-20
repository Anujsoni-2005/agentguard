"""
AgentGuard Rate Limiting §3.7.3
"""
import time
import math
import tldextract
from typing import Tuple, Dict, Optional

class TokenBucket:
    def __init__(self, capacity: int, refill_per_s: float):
        self.capacity = float(capacity)
        self.refill_per_s = refill_per_s
        self.tokens = float(capacity)
        self.last_update = time.monotonic()

    def consume(self, amount: float = 1.0) -> Tuple[bool, Optional[int]]:
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_s)
        self.last_update = now

        if self.tokens < amount:
            needed = amount - self.tokens
            retry_after_ms = math.ceil((needed / self.refill_per_s) * 1000) if self.refill_per_s > 0 else 0
            return False, retry_after_ms
        
        self.tokens -= amount
        return True, None

class RateLimiter:
    def __init__(self):
        self.buckets: Dict[Tuple, TokenBucket] = {}
        # Offline mode TLD extract
        self.extract = tldextract.TLDExtract(suffix_list_urls=None)

    def get_bucket(self, key: Tuple, capacity: int, refill_per_min: int) -> TokenBucket:
        if key not in self.buckets:
            self.buckets[key] = TokenBucket(capacity, refill_per_min / 60.0)
        # Update parameters if policy changed (simplification for now)
        bucket = self.buckets[key]
        bucket.capacity = float(capacity)
        bucket.refill_per_s = refill_per_min / 60.0
        return bucket

    def check(self, run_id: str, host: str, run_capacity: int, run_refill_min: int, dom_capacity: int, dom_refill_min: int) -> Tuple[bool, Optional[int]]:
        """
        Check both run-level and domain-level rate limits.
        Returns (is_allowed, retry_after_ms)
        """
        run_bucket = self.get_bucket(("run", run_id), run_capacity, run_refill_min)
        
        # registered domain = eTLD+1
        ext = self.extract(host)
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        
        dom_bucket = self.get_bucket(("dom", run_id, registered_domain), dom_capacity, dom_refill_min)
        
        # Note: A strict implementation consumes from both only if both succeed, 
        # but consuming independently is fine for rate limiting. 
        # Let's peek first if possible, or just consume and let the strictest win.
        # To avoid state mutation on failure, we should ideally peek.
        
        # Peek run
        now = time.monotonic()
        run_tokens = min(run_bucket.capacity, run_bucket.tokens + (now - run_bucket.last_update) * run_bucket.refill_per_s)
        dom_tokens = min(dom_bucket.capacity, dom_bucket.tokens + (now - dom_bucket.last_update) * dom_bucket.refill_per_s)
        
        if run_tokens < 1.0 or dom_tokens < 1.0:
            retry_run = math.ceil(((1.0 - run_tokens) / run_bucket.refill_per_s) * 1000) if run_tokens < 1.0 and run_bucket.refill_per_s > 0 else 0
            retry_dom = math.ceil(((1.0 - dom_tokens) / dom_bucket.refill_per_s) * 1000) if dom_tokens < 1.0 and dom_bucket.refill_per_s > 0 else 0
            return False, max(retry_run, retry_dom)
            
        # Consume both
        run_bucket.consume()
        dom_bucket.consume()
        return True, None
