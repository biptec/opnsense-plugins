<?php
namespace OPNsense\ApiExtensions;

final class InterfaceSync
{
    public const VERSION = 2;
    public const HA_SYNC_ITEM = 'interface_vlans';

    private const POLICY_ID = '/^[a-z][a-z0-9_-]{0,31}$/D';
    private const INTERFACE_ID = '/^[A-Za-z0-9_.:-]{1,64}$/D';
    private const MAX_SYNC_INTERFACE_ID_LENGTH = 20;

    private static function fail(string $message): void
    {
        throw new \InvalidArgumentException($message);
    }

    private static function flag($value): bool
    {
        return in_array($value, [1, '1', true, 'yes', 'on'], true);
    }

    private static function rows($value): array
    {
        if ($value === null || $value === '') {
            return [];
        }
        if (!is_array($value)) {
            self::fail('interface sync policy list must be an array');
        }
        if (!array_is_list($value)) {
            return [$value];
        }
        return array_values($value);
    }

    private static function containerRows($container, string $item, string $label): array
    {
        if ($container === null || $container === '') {
            return [];
        }
        if (!is_array($container)) {
            self::fail($label . ' must be an object');
        }
        return self::rows($container[$item] ?? []);
    }

    private static function policyRows(array $root): array
    {
        $shared = $root['shared'] ?? [];
        if ($shared === null || $shared === '') {
            return [];
        }
        if (!is_array($shared)) {
            self::fail('interface sync shared policy container must be an object');
        }
        return self::containerRows($shared['policies'] ?? [], 'policy', 'interface sync policies container');
    }

    private static function modelRoot(array $config): array
    {
        $root = $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'] ?? [];
        if ($root === '' || $root === null) {
            return [];
        }
        if (!is_array($root)) {
            self::fail('InterfaceSyncPolicy configuration must be an object');
        }
        return $root;
    }

    private static function policyId($value): string
    {
        $value = trim((string)$value);
        if (!preg_match(self::POLICY_ID, $value)) {
            self::fail('invalid interface sync policy id');
        }
        return $value;
    }

    private static function interfaceId($value): string
    {
        $value = trim((string)$value);
        if (!preg_match(self::INTERFACE_ID, $value)) {
            self::fail('invalid logical interface identifier');
        }
        return $value;
    }

    private static function syncInterfaceId($value): string
    {
        $value = self::interfaceId($value);
        if (strlen($value) > self::MAX_SYNC_INTERFACE_ID_LENGTH) {
            self::fail(sprintf(
                'policy-managed interface identifier %s exceeds the %d-character PF-safe synchronization limit',
                $value,
                self::MAX_SYNC_INTERFACE_ID_LENGTH
            ));
        }
        return $value;
    }

    public static function isEnabled(array $config): bool
    {
        $items = preg_split('/[\s,]+/', trim((string)($config['hasync']['syncitems'] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
        return in_array(self::HA_SYNC_ITEM, $items ?: [], true);
    }

    public static function policies(array $config): array
    {
        $root = self::modelRoot($config);
        $out = [];
        foreach (self::policyRows($root) as $row) {
            if (!is_array($row)) {
                self::fail('invalid interface sync policy record');
            }
            $id = self::policyId($row['id'] ?? '');
            if (isset($out[$id])) {
                self::fail('duplicate interface sync policy id ' . $id);
            }
            $uuid = trim((string)($row['@attributes']['uuid'] ?? ''));
            if ($uuid === '') {
                self::fail('interface sync policy ' . $id . ' is missing its MVC UUID');
            }
            $out[$id] = [
                'id' => $id,
                'uuid' => $uuid,
                'description' => trim((string)($row['description'] ?? '')),
                'synchronize' => self::flag($row['synchronize'] ?? null),
            ];
        }
        return $out;
    }

    public static function assignments(array $config): array
    {
        $root = self::modelRoot($config);
        $policies = self::policies($config);
        $policyByUuid = [];
        foreach ($policies as $policyId => $policy) {
            $policyByUuid[$policy['uuid']] = $policyId;
        }
        $out = [];
        foreach (self::containerRows($root['assignments'] ?? [], 'assignment', 'interface sync assignments container') as $row) {
            if (!is_array($row)) {
                self::fail('invalid interface policy assignment record');
            }
            $identifier = self::interfaceId($row['interface'] ?? '');
            $policyRef = trim((string)($row['policy_id'] ?? ''));
            if (isset($policies[$policyRef])) {
                // Compatibility with the short-lived development format that stored the stable ID directly.
                $policyId = $policyRef;
            } elseif (isset($policyByUuid[$policyRef])) {
                $policyId = $policyByUuid[$policyRef];
            } else {
                self::fail(sprintf('interface %s references unknown policy relation %s', $identifier, $policyRef));
            }
            if (isset($out[$identifier])) {
                self::fail('duplicate interface policy assignment ' . $identifier);
            }
            $out[$identifier] = [
                'interface' => $identifier,
                'policy_id' => $policyId,
                'policy_uuid' => $policies[$policyId]['uuid'],
                '@attributes' => is_array($row['@attributes'] ?? null) ? $row['@attributes'] : [],
            ];
        }
        return $out;
    }

    public static function replicas(array $config): array
    {
        $root = self::modelRoot($config);
        $out = [];
        foreach (self::containerRows($root['replicas'] ?? [], 'replica', 'interface sync replicas container') as $row) {
            if (!is_array($row)) {
                self::fail('invalid HA replica ownership record');
            }
            $identifier = self::interfaceId($row['interface'] ?? '');
            $policyId = self::policyId($row['policy_id'] ?? '');
            if (isset($out[$identifier])) {
                self::fail('duplicate HA replica ownership record ' . $identifier);
            }
            $out[$identifier] = [
                'interface' => $identifier,
                'policy_id' => $policyId,
                '@attributes' => is_array($row['@attributes'] ?? null) ? $row['@attributes'] : [],
            ];
        }
        return $out;
    }

    public static function validateCoverage(array $config, array $identifiers): void
    {
        $assignments = self::assignments($config);
        foreach ($identifiers as $identifier) {
            $identifier = self::interfaceId($identifier);
            if (!isset($assignments[$identifier])) {
                self::fail(sprintf('interface %s has no mandatory HA policy assignment', $identifier));
            }
        }
    }

    private static function tag($value): int
    {
        if (is_int($value)) {
            $tag = $value;
        } elseif (is_string($value) && preg_match('/^[0-9]+$/D', $value)) {
            $tag = (int)$value;
        } else {
            self::fail('invalid VLAN tag');
        }
        if ($tag < 1 || $tag > 4094) {
            self::fail('VLAN tag must be in range 1..4094');
        }
        return $tag;
    }

    private static function device($value, int $tag): string
    {
        $device = trim((string)$value);
        if ($device !== 'vlan' . $tag) {
            self::fail(sprintf('policy-managed VLAN device must equal vlan%d', $tag));
        }
        return $device;
    }

    private static function description($value): string
    {
        $value = trim((string)$value);
        if ($value === '' || strlen($value) > 255 || preg_match('/[\x00-\x1f\x7f]/', $value)) {
            self::fail('interface description must be printable and 1..255 bytes');
        }
        return $value;
    }

    private static function vlanList(array $config): array
    {
        $rows = $config['vlans']['vlan'] ?? [];
        if ($rows === '' || $rows === null) {
            return [];
        }
        if (!is_array($rows)) {
            self::fail('vlans.vlan must be an array');
        }
        return array_values($rows);
    }

    private static function vlanMap(array $config): array
    {
        $out = [];
        foreach (self::vlanList($config) as $row) {
            if (!is_array($row) || trim((string)($row['vlanif'] ?? '')) === '') {
                self::fail('invalid VLAN record');
            }
            $device = trim((string)$row['vlanif']);
            if (isset($out[$device])) {
                self::fail('duplicate VLAN device ' . $device);
            }
            $out[$device] = $row;
        }
        return $out;
    }

    private static function sourceInterface(string $id, string $policyId, array $ifc, array $vlans): array
    {
        $id = self::syncInterfaceId($id);
        self::policyId($policyId);
        if (!self::flag($ifc['enable'] ?? null)) {
            self::fail(sprintf('policy-managed interface %s must be enabled', $id));
        }
        if (self::flag($ifc['gateway_interface'] ?? null) ||
            self::flag($ifc['blockpriv'] ?? null) ||
            self::flag($ifc['blockbogons'] ?? null)) {
            self::fail(sprintf('policy-managed interface %s must be L2-only', $id));
        }
        foreach (['ipaddr', 'subnet', 'gateway', 'ipaddrv6', 'subnetv6', 'gatewayv6'] as $field) {
            if (trim((string)($ifc[$field] ?? '')) !== '') {
                self::fail(sprintf('policy-managed interface %s must be L2-only', $id));
            }
        }
        $device = trim((string)($ifc['if'] ?? ''));
        if (!isset($vlans[$device])) {
            self::fail(sprintf('policy-managed interface %s references missing VLAN %s', $id, $device));
        }
        $vlan = $vlans[$device];
        $tag = self::tag($vlan['tag'] ?? null);
        self::device($device, $tag);
        if ((string)($vlan['pcp'] ?? '0') !== '0') {
            self::fail(sprintf('policy-managed VLAN %s PCP must be 0', $device));
        }
        $proto = trim((string)($vlan['proto'] ?? ''));
        if ($proto !== '' && $proto !== '802.1q') {
            self::fail(sprintf('policy-managed VLAN %s must use 802.1q', $device));
        }
        return [
            'identifier' => $id,
            'policy_id' => $policyId,
            'description' => self::description($ifc['descr'] ?? ''),
            'tag' => $tag,
            'device' => $device,
        ];
    }

    public static function buildPayload(array $config, bool $prune = true): array
    {
        if (!self::isEnabled($config)) {
            self::fail('Policy-managed Interfaces / VLANs is not enabled in High Availability synchronization');
        }
        $interfaces = $config['interfaces'] ?? [];
        if (!is_array($interfaces)) {
            self::fail('interfaces must be an array');
        }
        self::validateCoverage($config, array_keys($interfaces));
        $vlans = self::vlanMap($config);
        $policies = self::policies($config);
        $assignments = self::assignments($config);
        $out = [];
        foreach ($assignments as $id => $assignment) {
            $policy = $policies[$assignment['policy_id']];
            if (!$policy['synchronize']) {
                continue;
            }
            if (!isset($interfaces[$id]) || !is_array($interfaces[$id])) {
                self::fail(sprintf('policy assignment references missing interface %s', $id));
            }
            $out[] = self::sourceInterface($id, $assignment['policy_id'], $interfaces[$id], $vlans);
        }
        usort($out, fn($a, $b) => strcmp($a['identifier'], $b['identifier']));
        $payloadPolicies = [];
        foreach ($policies as $policy) {
            $payloadPolicies[] = [
                'id' => $policy['id'],
                'description' => $policy['description'],
                'synchronize' => $policy['synchronize'],
            ];
        }
        return [
            'version' => self::VERSION,
            'policies' => $payloadPolicies,
            'interfaces' => $out,
            'prune' => $prune,
        ];
    }

    public static function validatePayload($payload): array
    {
        if (!is_array($payload) || array_diff(array_keys($payload), ['version', 'policies', 'interfaces', 'prune']) ||
            !array_key_exists('version', $payload) || !array_key_exists('policies', $payload) ||
            !array_key_exists('interfaces', $payload) || !array_key_exists('prune', $payload)) {
            self::fail('invalid interface sync payload');
        }
        if ($payload['version'] !== self::VERSION || !is_array($payload['policies']) ||
            !is_array($payload['interfaces']) || !is_bool($payload['prune'])) {
            self::fail('unsupported interface sync payload');
        }
        $policyOut = [];
        $policyIds = [];
        foreach (array_values($payload['policies']) as $row) {
            if (!is_array($row) || array_diff(array_keys($row), ['id', 'description', 'synchronize']) || count($row) !== 3) {
                self::fail('invalid interface sync policy record');
            }
            $id = self::policyId($row['id']);
            if (isset($policyIds[$id])) {
                self::fail('duplicate interface sync policy id ' . $id);
            }
            $policyIds[$id] = true;
            $policyOut[] = [
                'id' => $id,
                'description' => self::description($row['description']),
                'synchronize' => self::flag($row['synchronize']),
            ];
        }
        usort($policyOut, fn($a, $b) => strcmp($a['id'], $b['id']));

        $out = [];
        $ids = $devices = $tags = [];
        foreach (array_values($payload['interfaces']) as $row) {
            if (!is_array($row) || array_diff(array_keys($row), ['identifier', 'policy_id', 'description', 'tag', 'device']) ||
                count($row) !== 5) {
                self::fail('invalid interface sync record');
            }
            $id = self::syncInterfaceId($row['identifier']);
            $policyId = self::policyId($row['policy_id']);
            if (!isset($policyIds[$policyId])) {
                self::fail(sprintf('interface %s references policy %s missing from payload', $id, $policyId));
            }
            $tag = self::tag($row['tag']);
            $device = self::device($row['device'], $tag);
            if (isset($ids[$id]) || isset($devices[$device]) || isset($tags[$tag])) {
                self::fail('duplicate interface identifier, device, or tag');
            }
            $ids[$id] = $devices[$device] = $tags[$tag] = true;
            $out[] = [
                'identifier' => $id,
                'policy_id' => $policyId,
                'description' => self::description($row['description']),
                'tag' => $tag,
                'device' => $device,
            ];
        }
        usort($out, fn($a, $b) => strcmp($a['identifier'], $b['identifier']));
        return [
            'version' => self::VERSION,
            'policies' => $policyOut,
            'interfaces' => $out,
            'prune' => $payload['prune'],
        ];
    }

    private static function interfaceInScope($value, array $scope): bool
    {
        if (is_array($value)) {
            foreach ($value as $item) {
                if (self::interfaceInScope($item, $scope)) {
                    return true;
                }
            }
            return false;
        }
        foreach (preg_split('/[,\s]+/', trim((string)$value), -1, PREG_SPLIT_NO_EMPTY) as $identifier) {
            if (isset($scope[$identifier])) {
                return true;
            }
        }
        return false;
    }

    private static function clearNoSyncRecords(array &$records, array $scope): int
    {
        $changed = 0;
        if (array_key_exists('interface', $records)) {
            if (self::interfaceInScope($records['interface'], $scope) && self::flag($records['nosync'] ?? null)) {
                unset($records['nosync']);
                $changed++;
            }
            return $changed;
        }
        foreach ($records as &$record) {
            if (!is_array($record)) {
                continue;
            }
            if (self::interfaceInScope($record['interface'] ?? '', $scope) && self::flag($record['nosync'] ?? null)) {
                unset($record['nosync']);
                $changed++;
            }
        }
        unset($record);
        return $changed;
    }

    private static function adoptNativeRecords(array &$config, array $identifiers): array
    {
        $scope = array_fill_keys($identifiers, true);
        $result = ['virtualip' => 0, 'gateways' => 0, 'rules' => 0];
        if ($scope === []) {
            return $result;
        }

        if (isset($config['virtualip']['vip']) && is_array($config['virtualip']['vip'])) {
            $result['virtualip'] += self::clearNoSyncRecords($config['virtualip']['vip'], $scope);
        }
        if (isset($config['gateways']['gateway_item']) && is_array($config['gateways']['gateway_item'])) {
            $result['gateways'] += self::clearNoSyncRecords($config['gateways']['gateway_item'], $scope);
        }
        if (isset($config['OPNsense']['Gateways']['gateway_item']) && is_array($config['OPNsense']['Gateways']['gateway_item'])) {
            $result['gateways'] += self::clearNoSyncRecords($config['OPNsense']['Gateways']['gateway_item'], $scope);
        }
        if (isset($config['filter']['rule']) && is_array($config['filter']['rule'])) {
            $result['rules'] += self::clearNoSyncRecords($config['filter']['rule'], $scope);
        }
        if (
            isset($config['OPNsense']['Firewall']['Filter']['rules']['rule']) &&
            is_array($config['OPNsense']['Firewall']['Filter']['rules']['rule'])
        ) {
            $result['rules'] += self::clearNoSyncRecords($config['OPNsense']['Firewall']['Filter']['rules']['rule'], $scope);
        }
        return $result;
    }

    public static function localTrunkParent(array $config): string
    {
        $id = trim((string)($config['hasync']['pfsyncinterface'] ?? ''));
        $device = trim((string)($config['interfaces'][$id]['if'] ?? ''));
        if ($id === '' || $device === '') {
            self::fail('HA pfsync interface is not configured');
        }
        foreach (self::vlanList($config) as $vlan) {
            if (($vlan['vlanif'] ?? '') === $device) {
                $parent = trim((string)($vlan['if'] ?? ''));
                if ($parent !== '') {
                    return $parent;
                }
            }
        }
        self::fail('HA pfsync interface is not backed by a VLAN parent');
    }

    private static function policyRowsRaw(array $config): array
    {
        return self::policyRows(self::modelRoot($config));
    }

    private static function &modelRootForWrite(array &$config): array
    {
        if (!isset($config['OPNsense']) || !is_array($config['OPNsense'])) {
            $config['OPNsense'] = [];
        }
        if (!isset($config['OPNsense']['ApiExtensions']) || !is_array($config['OPNsense']['ApiExtensions'])) {
            $config['OPNsense']['ApiExtensions'] = [];
        }
        if (!isset($config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']) ||
            !is_array($config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'])) {
            $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'] = [];
        }
        return $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'];
    }

    private static function serializeRows(string $item, array $rows)
    {
        $rows = array_values($rows);
        if ($rows === []) {
            return '';
        }
        return [$item => count($rows) === 1 ? $rows[0] : $rows];
    }

    private static function setPolicyRows(array &$config, array $rows): void
    {
        $root =& self::modelRootForWrite($config);
        if (!isset($root['shared']) || !is_array($root['shared'])) {
            $root['shared'] = [];
        }
        $root['shared']['policies'] = self::serializeRows('policy', $rows);
    }

    private static function assignmentRowsRaw(array $config): array
    {
        $root = self::modelRoot($config);
        return self::containerRows($root['assignments'] ?? [], 'assignment', 'interface sync assignments container');
    }

    private static function setAssignmentRows(array &$config, array $rows): void
    {
        $root =& self::modelRootForWrite($config);
        $root['assignments'] = self::serializeRows('assignment', $rows);
    }

    private static function setReplicaRows(array &$config, array $rows): void
    {
        $root =& self::modelRootForWrite($config);
        $root['replicas'] = self::serializeRows('replica', $rows);
    }

    public static function reconcilePolicies(array &$config, array $payload, callable $uuidFactory): array
    {
        $current = [];
        foreach (self::policyRowsRaw($config) as $row) {
            if (!is_array($row)) {
                self::fail('invalid interface sync policy record');
            }
            $id = self::policyId($row['id'] ?? '');
            if (isset($current[$id])) {
                self::fail('duplicate interface sync policy id ' . $id);
            }
            $current[$id] = $row;
        }

        $desired = [];
        foreach ($payload['policies'] as $row) {
            $desired[$row['id']] = $row;
        }

        $keep = [];
        if (!$payload['prune']) {
            foreach ($current as $id => $row) {
                if (!isset($desired[$id])) {
                    $keep[$id] = $row;
                }
            }
        } else {
            $references = [];
            foreach (self::assignments($config) as $row) {
                $references[$row['policy_id']] = true;
            }
            foreach (self::replicas($config) as $row) {
                $references[$row['policy_id']] = true;
            }

            // The policy model is shared by interface and HAProxy object assignments. A policy
            // may be local-only on the receiver yet still be referenced by a local HAProxy
            // object, so interface synchronization must not prune it merely because there is no
            // interface assignment using it.
            $policyByReference = [];
            foreach ($current as $id => $row) {
                $policyByReference[$id] = $id;
                $uuid = trim((string)($row['@attributes']['uuid'] ?? ''));
                if ($uuid !== '') {
                    $policyByReference[$uuid] = $id;
                }
            }
            $root = self::modelRoot($config);
            foreach ([
                ['haproxy_assignments', 'assignment'],
                ['haproxy_replicas', 'replica'],
            ] as [$container, $item]) {
                foreach (self::containerRows(
                    $root[$container] ?? [],
                    $item,
                    'HAProxy policy reference container'
                ) as $row) {
                    if (!is_array($row)) {
                        continue;
                    }
                    $reference = trim((string)($row['policy_id'] ?? ''));
                    if ($reference === '') {
                        continue;
                    }
                    if (!isset($policyByReference[$reference])) {
                        self::fail('HAProxy object references unknown interface sync policy relation ' . $reference);
                    }
                    $references[$policyByReference[$reference]] = true;
                }
            }
            foreach ($current as $id => $row) {
                if (!isset($desired[$id]) && isset($references[$id])) {
                    self::fail(sprintf('cannot prune interface policy %s while it is still assigned locally or to an HA replica', $id));
                }
            }
        }

        foreach ($desired as $id => $row) {
            $attributes = is_array($current[$id]['@attributes'] ?? null) ? $current[$id]['@attributes'] : [];
            if (empty($attributes['uuid'])) {
                $uuid = trim((string)$uuidFactory());
                if ($uuid === '') {
                    throw new \RuntimeException('UUID factory returned empty value');
                }
                $attributes = ['uuid' => $uuid];
            }
            $keep[$id] = [
                '@attributes' => $attributes,
                'id' => $id,
                'description' => $row['description'],
                'synchronize' => $row['synchronize'] ? '1' : '0',
            ];
        }

        ksort($keep);
        self::setPolicyRows($config, array_values($keep));
        return [
            'desired' => count($desired),
            'retained_local' => count($keep) - count($desired),
        ];
    }

    public static function reconcile(array $config, $payload, ?callable $uuidFactory = null): array
    {
        $payload = self::validatePayload($payload);
        $parent = self::localTrunkParent($config);
        $uuidFactory ??= fn() => bin2hex(random_bytes(16));
        $interfaces = $config['interfaces'] ?? [];
        if (!is_array($interfaces)) {
            self::fail('interfaces must be an array');
        }
        $vlans = self::vlanList($config);
        $vmap = self::vlanMap($config);
        $replicas = self::replicas($config);
        $localAssignments = self::assignments($config);

        $desired = $desiredDevices = [];
        foreach ($payload['interfaces'] as $row) {
            $desired[$row['identifier']] = $row;
            $desiredDevices[$row['device']] = true;
        }

        // Existing dual-node objects are adopted only when the receiver has an explicit
        // local assignment with the same policy. No interface-name convention participates.
        $adoptedLocal = [];
        foreach ($desired as $id => $row) {
            if (isset($replicas[$id])) {
                continue;
            }
            if (isset($localAssignments[$id])) {
                if ($localAssignments[$id]['policy_id'] !== $row['policy_id']) {
                    self::fail(sprintf(
                        'cannot adopt interface %s: local policy %s differs from peer policy %s',
                        $id,
                        $localAssignments[$id]['policy_id'],
                        $row['policy_id']
                    ));
                }
                $adoptedLocal[$id] = $localAssignments[$id];
            }
        }

        $managed = $replicas + $adoptedLocal;
        $current = $currentDevices = $otherDevices = [];
        foreach ($interfaces as $id => $ifc) {
            if (!is_array($ifc)) {
                continue;
            }
            $device = trim((string)($ifc['if'] ?? ''));
            if (isset($managed[$id])) {
                $current[(string)$id] = $ifc;
                if ($device !== '') {
                    $currentDevices[$device] = (string)$id;
                }
            } elseif ($device !== '') {
                $otherDevices[$device] = (string)$id;
            }
        }

        foreach ($desired as $id => $row) {
            if (isset($interfaces[$id]) && !isset($managed[$id])) {
                self::fail(sprintf('policy-managed interface identifier %s is already owned locally', $id));
            }
            if (isset($otherDevices[$row['device']])) {
                self::fail(sprintf(
                    'policy-managed VLAN device %s is used by local interface %s',
                    $row['device'],
                    $otherDevices[$row['device']]
                ));
            }
            if (isset($vmap[$row['device']]) && !isset($currentDevices[$row['device']])) {
                self::fail('policy-managed VLAN device collides with local VLAN');
            }
            foreach ($vlans as $vlan) {
                $device = trim((string)($vlan['vlanif'] ?? ''));
                if (trim((string)($vlan['if'] ?? '')) === $parent &&
                    self::tag($vlan['tag'] ?? null) === $row['tag'] &&
                    $device !== $row['device'] && !isset($currentDevices[$device])) {
                    self::fail('policy-managed VLAN tag collides with local VLAN');
                }
            }
        }

        $next = $config;
        foreach (array_keys($current) as $id) {
            if ($payload['prune'] || isset($desired[$id])) {
                unset($next['interfaces'][$id]);
            }
        }
        $reset = $configureIf = [];
        foreach ($desired as $id => $row) {
            $next['interfaces'][$id] = [
                'if' => $row['device'], 'descr' => $row['description'], 'lock' => '0', 'enable' => '1',
            ];
            $old = $current[$id] ?? null;
            if ($old === null) {
                $configureIf[] = $id;
            } elseif (trim((string)($old['if'] ?? '')) !== $row['device'] || !self::flag($old['enable'] ?? null)) {
                $reset[] = $configureIf[] = $id;
            }
        }
        if ($payload['prune']) {
            foreach ($current as $id => $_) {
                if (!isset($desired[$id])) {
                    $reset[] = $id;
                }
            }
        }

        $rewriteDevices = [];
        foreach ($currentDevices as $device => $id) {
            if ($payload['prune'] || isset($desired[$id])) {
                $rewriteDevices[$device] = $id;
            }
        }
        $kept = [];
        foreach ($vlans as $vlan) {
            if (!isset($rewriteDevices[trim((string)($vlan['vlanif'] ?? ''))])) {
                $kept[] = $vlan;
            }
        }
        $configureVlan = [];
        foreach ($desired as $row) {
            $old = $vmap[$row['device']] ?? null;
            $uuid = is_array($old) ? trim((string)($old['@attributes']['uuid'] ?? '')) : '';
            if ($uuid === '') {
                $uuid = trim((string)$uuidFactory());
                if ($uuid === '') {
                    throw new \RuntimeException('UUID factory returned empty value');
                }
            }
            if ($old === null || trim((string)($old['if'] ?? '')) !== $parent ||
                self::tag($old['tag'] ?? null) !== $row['tag'] ||
                (string)($old['pcp'] ?? '0') !== '0') {
                $configureVlan[] = $row['device'];
            }
            $kept[] = [
                '@attributes' => ['uuid' => $uuid],
                'if' => $parent,
                'tag' => (string)$row['tag'],
                'pcp' => '0',
                'proto' => '',
                'descr' => $row['description'],
                'vlanif' => $row['device'],
            ];
        }
        $next['vlans']['vlan'] = array_values($kept);

        // Convert an explicitly matching legacy local assignment into HA-replica ownership.
        if ($adoptedLocal !== []) {
            $remainingAssignments = [];
            foreach (self::assignmentRowsRaw($next) as $row) {
                $id = trim((string)($row['interface'] ?? ''));
                if (!isset($adoptedLocal[$id])) {
                    $remainingAssignments[] = $row;
                }
            }
            self::setAssignmentRows($next, $remainingAssignments);
        }

        // Replica ownership is the only authority for destructive prune on the receiver.
        // During prepare, stale replicas stay registered; prune removes them after native sync.
        $replicaRows = [];
        if (!$payload['prune']) {
            foreach ($replicas as $id => $row) {
                if (!isset($desired[$id])) {
                    $replicaRows[] = [
                        '@attributes' => $row['@attributes'],
                        'interface' => $id,
                        'policy_id' => $row['policy_id'],
                    ];
                }
            }
        }
        foreach ($desired as $id => $row) {
            $attributes = $replicas[$id]['@attributes'] ?? [];
            if (empty($attributes['uuid'])) {
                $uuid = trim((string)$uuidFactory());
                if ($uuid === '') {
                    throw new \RuntimeException('UUID factory returned empty value');
                }
                $attributes = ['uuid' => $uuid];
            }
            $replicaRows[] = [
                '@attributes' => $attributes,
                'interface' => $id,
                'policy_id' => $row['policy_id'],
            ];
        }
        self::setReplicaRows($next, $replicaRows);
        $policyPlan = self::reconcilePolicies($next, $payload, $uuidFactory);

        $adoptIdentifiers = array_values(array_unique(array_merge(array_keys($current), array_keys($desired))));
        $adoptedNoSync = self::adoptNativeRecords($next, $adoptIdentifiers);

        $destroy = [];
        foreach ($currentDevices as $device => $id) {
            $idDesired = isset($desired[$id]);
            $deviceChanged = $idDesired && $desired[$id]['device'] !== $device;
            if (
                ($payload['prune'] && !$idDesired) ||
                $deviceChanged ||
                ($idDesired && !$deviceChanged && in_array($device, $configureVlan, true))
            ) {
                $destroy[] = $device;
            }
        }
        foreach (['reset', 'configureIf', 'configureVlan', 'destroy'] as $name) {
            $$name = array_values(array_unique($$name));
            sort($$name);
        }
        return [
            'config' => $next,
            'changed' => $next !== $config,
            'count' => count($desired),
            'parent' => $parent,
            'plan' => [
                'reset_interfaces' => $reset,
                'destroy_vlans' => $destroy,
                'configure_vlans' => $configureVlan,
                'configure_interfaces' => $configureIf,
                'adopted_nosync' => $adoptedNoSync,
                'adopted_local_assignments' => array_keys($adoptedLocal),
                'policies' => $policyPlan,
            ],
        ];
    }
}
