# Issue #103: mixed-version native HA acceptance fixture

The test `test_mixed_version_v2.php` exercises the **actual old Plugins code**
from immutable OPNsense Plugins commit
`7dc9649eef6f86d837fa47fb1edaef6d5a790b36`. The old code, not the new
code, produces the checked-in `legacy_etna_v2_payload.json`.

The interface fixture contains the exact new Ubuntu endpoint logical
identifier `ep_ha_issue_00474f9e`, VLAN `3990`, and policy `endpoint`.
The HAProxy fixture contains a linked healthcheck, server and backend,
preserving stable semantic names but not the sender's local object UUIDs.
Both categories use the same synthetic old-Etna core/services/endpoint
policy table, as they would on one actual router. A separate negative test
deliberately removes the local-only services policy from one category payload:
the receiver must retain its local definition while pruning a truly unused
synchronized policy omitted by the sender.

Regenerate using an **offline PHP 8.3 Docker container**, directly from the
old Git objects (no checkout change and no network inside container):

```sh
python3 sysutils/api-extensions/tests/generate_legacy_v2.py
python3 sysutils/api-extensions/tests/generate_legacy_v2.py --check
```

Run acceptance in PHP 8.3. When PHP is not installed in the Coder
workspace, use an isolated ephemeral container instead. From the Plugins
repository root:

```sh
tar -c \
  sysutils/api-extensions/tests/test_endpoint_sync.php \
  sysutils/api-extensions/tests/test_interface_sync.php \
  sysutils/api-extensions/tests/test_mixed_version_v2.php \
  sysutils/api-extensions/tests/test_haproxy_sync.php \
  sysutils/api-extensions/tests/legacy_etna_v2_payload.json \
  sysutils/api-extensions/src/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php \
  sysutils/api-extensions/src/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxySync.php \
  sysutils/api-extensions/src/etc/inc/plugins.inc.d/api_extensions.inc \
  | docker run --rm --network none --memory 128m -i php:8.3-cli-alpine \
      sh -ec 'mkdir -p /qa; tar -xf - -C /qa; cd /qa; \
        php sysutils/api-extensions/tests/test_endpoint_sync.php; \
        php sysutils/api-extensions/tests/test_haproxy_sync.php'
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
