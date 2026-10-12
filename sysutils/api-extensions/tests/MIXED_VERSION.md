# Issue #103: mixed-version native HA acceptance fixture

The test `test_mixed_version_v2.php` exercises the **actual old Plugins code**
from immutable OPNsense Plugins commit
`7dc9649eef6f86d837fa47fb1edaef6d5a790b36`. The old code, not the new
code, produces the checked-in `legacy_etna_v2_payload.json`.

The interface fixture contains the exact new Ubuntu endpoint logical
identifier `ep_ha_issue_00474f9e`, VLAN `3990`, and policy `endpoint`.
The HAProxy fixture contains a linked healthcheck, server and backend,
preserving stable semantic names but not the sender's local object UUIDs.

Regenerate using an **offline PHP 8.3 Docker container**, directly from the
old Git objects (no checkout change and no network inside container):

```sh
python3 sysutils/api-extensions/tests/generate_legacy_v2.py
python3 sysutils/api-extensions/tests/generate_legacy_v2.py --check
```

Run acceptance in PHP 8.3:

```sh
php sysutils/api-extensions/tests/test_endpoint_sync.php
php sysutils/api-extensions/tests/test_haproxy_sync.php
```

`test_endpoint_sync.php` now includes the mixed-version test. The test covers:

- Old Etna v2 interface prepare/finalize to new Rigi.
- Local Rigi HA VLAN/core WAN and policy assignment preservation.
- Regular (not replica) endpoint assignments on Rigi.
- Old Etna HAProxy healthcheck/server/backend graph into Rigi.
- Preservation of Rigi's node-local HAProxy TLS frontend.
- New Rigi to freshly installed new Etna for both Interfaces and HAProxy.
- Different local UUIDs, identical semantic policies and payloads.
- Repeated sync idempotence, without owner/replica handoff.

This fixture is **synthetic test data**, not a dump of a real router, Terraform
state, production IPs, passwords, credentials or serial numbers. It is not a
substitute for the live Rigi-first, Etna-second HA acceptance in Issue #103.
