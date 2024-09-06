Design notes:

- Major:
  - DNS ID collisions could be bad? Could solve by adding client addr to key.
  - Handle custom resolving functions?
  - Nameservers should be configurable.
  - Could try to optimize requests in flight, but optimizing the cache might be a better solution.

- Cache:
  - Need to expire cache entries.
  - Need to cap size of cache.
  - Could be a bottleneck?

- Minor:
  - Would not be able to handle multiple queries in a single packet.
  - Missing niche features like EDNS0, DNSSEC, etc?

Decisions:
 - Pre-allocate space for every query ID.. Given max DNS message size of 512 bytes,
   this theoretically could be 65536 * 512 bytes = 32MB of RAM... That's a lot. But we
   clean up the memory after requests.