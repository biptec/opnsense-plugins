<?php
namespace OPNsense\ApiExtensions;

final class EndpointSync
{
    public const VERSION = 1;
    private const ID = '/^ep_[a-z0-9_]{1,20}_[0-9a-f]{8}$/D';

    private static function fail(string $message): void
    {
        throw new \InvalidArgumentException($message);
    }

    public static function isEndpointIdentifier(string $id): bool
    {
        return preg_match(self::ID, $id) === 1;
    }

    private static function flag($value): bool
    {
        return in_array($value, [1, '1', true, 'yes', 'on'], true);
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
            self::fail(sprintf('endpoint VLAN device must equal vlan%d', $tag));
        }
        return $device;
    }

    private static function description($value): string
    {
        $value = trim((string)$value);
        if ($value === '' || strlen($value) > 255 || preg_match('/[\x00-\x1f\x7f]/', $value)) {
            self::fail('endpoint description must be printable and 1..255 bytes');
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

    private static function sourceEndpoint(string $id, array $ifc, array $vlans): array
    {
        if (!self::isEndpointIdentifier($id)) {
            self::fail('invalid endpoint identifier ' . $id);
        }
        if (!self::flag($ifc['enable'] ?? null)) {
            self::fail('endpoint interface must be enabled');
        }
        if (self::flag($ifc['gateway_interface'] ?? null) ||
            self::flag($ifc['blockpriv'] ?? null) ||
            self::flag($ifc['blockbogons'] ?? null)) {
            self::fail('endpoint interface must be L2-only');
        }
        foreach (['ipaddr', 'subnet', 'gateway', 'ipaddrv6', 'subnetv6', 'gatewayv6'] as $field) {
            if (trim((string)($ifc[$field] ?? '')) !== '') {
                self::fail('endpoint interface must be L2-only');
            }
        }
        $device = trim((string)($ifc['if'] ?? ''));
        if (!isset($vlans[$device])) {
            self::fail('endpoint references missing VLAN ' . $device);
        }
        $vlan = $vlans[$device];
        $tag = self::tag($vlan['tag'] ?? null);
        self::device($device, $tag);
        if ((string)($vlan['pcp'] ?? '0') !== '0') {
            self::fail('endpoint VLAN PCP must be 0');
        }
        $proto = trim((string)($vlan['proto'] ?? ''));
        if ($proto !== '' && $proto !== '802.1q') {
            self::fail('endpoint VLAN must use 802.1q');
        }
        return [
            'identifier' => $id,
            'description' => self::description($ifc['descr'] ?? ''),
            'tag' => $tag,
            'device' => $device,
        ];
    }

    public static function buildPayload(array $config, bool $prune = true): array
    {
        $interfaces = $config['interfaces'] ?? [];
        if (!is_array($interfaces)) {
            self::fail('interfaces must be an array');
        }
        $vlans = self::vlanMap($config);
        $out = [];
        foreach ($interfaces as $id => $ifc) {
            if (!str_starts_with((string)$id, 'ep_')) {
                continue;
            }
            if (!is_array($ifc)) {
                self::fail('endpoint interface must be an object');
            }
            $out[] = self::sourceEndpoint((string)$id, $ifc, $vlans);
        }
        usort($out, fn($a, $b) => strcmp($a['identifier'], $b['identifier']));
        return ['version' => self::VERSION, 'endpoints' => $out, 'prune' => $prune];
    }

    public static function validatePayload($payload): array
    {
        if (!is_array($payload) || array_diff(array_keys($payload), ['version', 'endpoints', 'prune']) ||
            !array_key_exists('version', $payload) || !array_key_exists('endpoints', $payload) || !array_key_exists('prune', $payload)) {
            self::fail('invalid endpoint sync payload');
        }
        if ($payload['version'] !== self::VERSION || !is_array($payload['endpoints']) || !is_bool($payload['prune'])) {
            self::fail('unsupported endpoint sync payload');
        }
        $out = [];
        $ids = $devices = $tags = [];
        foreach (array_values($payload['endpoints']) as $row) {
            if (!is_array($row) || array_diff(array_keys($row), ['identifier', 'description', 'tag', 'device']) ||
                count($row) !== 4) {
                self::fail('invalid endpoint sync record');
            }
            $id = trim((string)$row['identifier']);
            if (!self::isEndpointIdentifier($id)) {
                self::fail('invalid endpoint identifier');
            }
            $tag = self::tag($row['tag']);
            $device = self::device($row['device'], $tag);
            if (isset($ids[$id]) || isset($devices[$device]) || isset($tags[$tag])) {
                self::fail('duplicate endpoint identifier, device, or tag');
            }
            $ids[$id] = $devices[$device] = $tags[$tag] = true;
            $out[] = [
                'identifier' => $id,
                'description' => self::description($row['description']),
                'tag' => $tag,
                'device' => $device,
            ];
        }
        usort($out, fn($a, $b) => strcmp($a['identifier'], $b['identifier']));
        return ['version' => self::VERSION, 'endpoints' => $out, 'prune' => $payload['prune']];
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

    public static function reconcile(array $config, $payload, ?callable $uuidFactory = null): array
    {
        $payload = self::validatePayload($payload);
        $parent = self::localTrunkParent($config);
        $uuidFactory ??= fn() => bin2hex(random_bytes(16));
        $interfaces = $config['interfaces'] ?? [];
        $vlans = self::vlanList($config);
        $vmap = self::vlanMap($config);

        $current = $currentDevices = $otherDevices = [];
        foreach ($interfaces as $id => $ifc) {
            if (!is_array($ifc)) {
                continue;
            }
            $device = trim((string)($ifc['if'] ?? ''));
            if (self::isEndpointIdentifier((string)$id)) {
                $current[(string)$id] = $ifc;
                if ($device !== '') {
                    $currentDevices[$device] = true;
                }
            } elseif ($device !== '') {
                $otherDevices[$device] = (string)$id;
            }
        }

        $desired = $desiredDevices = [];
        foreach ($payload['endpoints'] as $row) {
            if (isset($otherDevices[$row['device']])) {
                self::fail('endpoint VLAN device is used by non-endpoint interface ' . $otherDevices[$row['device']]);
            }
            if (isset($vmap[$row['device']]) && !isset($currentDevices[$row['device']])) {
                self::fail('endpoint VLAN device collides with non-endpoint VLAN');
            }
            foreach ($vlans as $vlan) {
                $device = trim((string)($vlan['vlanif'] ?? ''));
                if (trim((string)($vlan['if'] ?? '')) === $parent &&
                    self::tag($vlan['tag'] ?? null) === $row['tag'] &&
                    $device !== $row['device'] && !isset($currentDevices[$device])) {
                    self::fail('endpoint VLAN tag collides with non-endpoint VLAN');
                }
            }
            $desired[$row['identifier']] = $row;
            $desiredDevices[$row['device']] = true;
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
            'changed' => $next != $config,
            'count' => count($desired),
            'parent' => $parent,
            'plan' => [
                'reset_interfaces' => $reset,
                'destroy_vlans' => $destroy,
                'configure_vlans' => $configureVlan,
                'configure_interfaces' => $configureIf,
            ],
        ];
    }
}
