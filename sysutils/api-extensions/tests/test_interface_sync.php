<?php
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';

use OPNsense\ApiExtensions\InterfaceSync;

function eq($expected, $actual, $message) {
    if ($expected !== $actual) {
        fwrite(STDERR, "$message\nexpected=" . var_export($expected, true) . "\nactual=" . var_export($actual, true) . "\n");
        exit(1);
    }
}
function bad($fn, $message) {
    try {
        $fn();
    } catch (\InvalidArgumentException $e) {
        return;
    }
    fwrite(STDERR, "$message: expected InvalidArgumentException\n");
    exit(1);
}
function model(array $policies, array $assignments = [], array $replicas = []): array {
    return [
        'shared' => ['policies' => ['policy' => array_map(fn($row) => array_merge(
            ['@attributes' => ['uuid' => 'p-' . $row['id']]],
            $row
        ), $policies)]],
        'assignments' => ['assignment' => array_map(fn($row) => array_merge(
            ['@attributes' => ['uuid' => 'a-' . $row['interface']]],
            $row
        ), $assignments)],
        'replicas' => ['replica' => array_map(fn($row) => array_merge(
            ['@attributes' => ['uuid' => 'r-' . $row['interface']]],
            $row
        ), $replicas)],
    ];
}
function base(): array {
    $config = [
        'hasync' => [
            'pfsyncinterface' => 'core_ha_control',
            'syncitems' => 'virtualip,rules,staticroutes,interface_vlans',
        ],
        'interfaces' => [
            'lan' => ['if' => 'vtnet0', 'descr' => 'Recovery', 'enable' => '1'],
            'core_ha_control' => ['if' => 'vlan1901', 'descr' => 'HA control', 'enable' => '1'],
            'core_wan' => ['if' => 'vlan3801', 'descr' => 'WAN', 'enable' => '1'],
        ],
        'vlans' => ['vlan' => [
            ['@attributes'=>['uuid'=>'ha'],'if'=>'vtnet1','tag'=>'1901','pcp'=>'0','proto'=>'','descr'=>'HA control','vlanif'=>'vlan1901'],
            ['@attributes'=>['uuid'=>'wan'],'if'=>'vtnet1','tag'=>'3801','pcp'=>'0','proto'=>'','descr'=>'WAN','vlanif'=>'vlan3801'],
        ]],
    ];
    $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'] = model(
        [
            ['id'=>'core','description'=>'Router core','synchronize'=>'0'],
            ['id'=>'services','description'=>'Node services','synchronize'=>'0'],
            ['id'=>'endpoint','description'=>'HA shared endpoint networks','synchronize'=>'1'],
        ],
        [
            ['interface'=>'lan','policy_id'=>'core'],
            ['interface'=>'core_ha_control','policy_id'=>'core'],
            ['interface'=>'core_wan','policy_id'=>'core'],
        ]
    );
    return $config;
}
function addSharedInterface(array $config, string $id = 'customer_net', int $tag = 777, string $policy = 'endpoint'): array {
    $config['interfaces'][$id] = ['if'=>'vlan'.$tag,'descr'=>'Customer network','lock'=>'0','enable'=>'1'];
    $config['vlans']['vlan'][] = [
        '@attributes'=>['uuid'=>'source-'.$tag],
        'if'=>'vtnet1','tag'=>(string)$tag,'pcp'=>'0','proto'=>'','descr'=>'Customer network','vlanif'=>'vlan'.$tag
    ];
    $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['assignments']['assignment'][] = [
        '@attributes'=>['uuid'=>'a-'.$id], 'interface'=>$id, 'policy_id'=>$policy
    ];
    return $config;
}

$source = addSharedInterface(base());
$payload = InterfaceSync::buildPayload($source);
eq('vtnet1', InterfaceSync::localTrunkParent($source), 'local parent');
eq(true, InterfaceSync::isEnabled($source), 'HA service enabled from hasync syncitems');
eq([
    'version'=>2,
    'policies'=>[
        ['id'=>'core','description'=>'Router core','synchronize'=>false],
        ['id'=>'services','description'=>'Node services','synchronize'=>false],
        ['id'=>'endpoint','description'=>'HA shared endpoint networks','synchronize'=>true],
    ],
    'interfaces'=>[[
        'identifier'=>'customer_net',
        'policy_id'=>'endpoint',
        'description'=>'Customer network',
        'tag'=>777,
        'device'=>'vlan777',
    ]],
    'prune'=>true,
], $payload, 'payload is policy-selected, not name-selected');

$localOnly = addSharedInterface(base(), 'manual_local', 778, 'core');
eq([], InterfaceSync::buildPayload($localOnly)['interfaces'], 'disabled policy excludes interface regardless of name');

$tooLong = addSharedInterface(base(), 'abcdefghijklmnopqrstu', 779, 'endpoint');
bad(fn()=>InterfaceSync::buildPayload($tooLong), 'syncable interface identifiers must remain PF-table-name safe');

$dynamic = base();
$dynamic['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['shared']['policies']['policy'][] = [
    '@attributes'=>['uuid'=>'p-lab-shared'],
    'id'=>'lab_shared',
    'description'=>'Operator-created shared lab policy',
    'synchronize'=>'1',
];
$dynamic = addSharedInterface($dynamic, 'customer_anything', 780, 'lab_shared');
$dynamicPayload = InterfaceSync::buildPayload($dynamic);
eq('lab_shared', $dynamicPayload['interfaces'][0]['policy_id'], 'new policy works without router code changes');
eq('customer_anything', $dynamicPayload['interfaces'][0]['identifier'], 'new policy is independent of naming conventions');
$dynamicReceiver = InterfaceSync::reconcile(base(), $dynamicPayload, fn()=>'dynamic-receiver-uuid');
eq(true, InterfaceSync::policies($dynamicReceiver['config'])['lab_shared']['synchronize'], 'dynamic policy is reconciled to peer by stable policy id');

$unassigned = base();
$unassigned['interfaces']['manual_unassigned'] = ['if'=>'vlan778','descr'=>'Unassigned','enable'=>'1'];
$unassigned['vlans']['vlan'][] = ['@attributes'=>['uuid'=>'u'],'if'=>'vtnet1','tag'=>'778','pcp'=>'0','proto'=>'','descr'=>'Unassigned','vlanif'=>'vlan778'];
bad(fn()=>InterfaceSync::buildPayload($unassigned), 'mandatory policy coverage');

$disabled = $source;
$disabled['hasync']['syncitems'] = 'virtualip,rules,staticroutes';
bad(fn()=>InterfaceSync::buildPayload($disabled), 'standard HA service checkbox is authoritative');

$serializedEmptyReceiver = base();
$serializedEmptyReceiver['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['replicas'] = '';
eq([], InterfaceSync::replicas($serializedEmptyReceiver), 'empty MVC replica container serializes as empty string');
$serializedEmptyCreate = InterfaceSync::reconcile($serializedEmptyReceiver, $payload, fn()=>'receiver-empty-container-uuid');
eq('endpoint', InterfaceSync::replicas($serializedEmptyCreate['config'])['customer_net']['policy_id'], 'empty serialized replica container accepts first HA replica');

$singletonReplicaReceiver = $serializedEmptyCreate['config'];
eq('customer_net', $singletonReplicaReceiver['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['replicas']['replica']['interface'], 'single replica is serialized in canonical OPNsense singleton form');
eq('endpoint', InterfaceSync::replicas($singletonReplicaReceiver)['customer_net']['policy_id'], 'singleton MVC replica record is normalized');

$r = InterfaceSync::reconcile(base(), $payload, fn()=>'receiver-uuid');
eq(true, $r['changed'], 'create changed');
eq(['vlan777'], $r['plan']['configure_vlans'], 'create vlan plan');
eq(['customer_net'], $r['plan']['configure_interfaces'], 'create interface plan');
eq('vlan777', $r['config']['interfaces']['customer_net']['if'], 'generic identifier created');
eq('endpoint', InterfaceSync::replicas($r['config'])['customer_net']['policy_id'], 'receiver ownership recorded explicitly');
eq(false, isset(InterfaceSync::assignments($r['config'])['customer_net']), 'replica is not a local assignment');
$policyRowsAfterCreate = $r['config']['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['shared']['policies']['policy'];
$endpointPolicyRows = array_values(array_filter($policyRowsAfterCreate, fn($row)=>($row['id'] ?? '') === 'endpoint'));
eq('p-endpoint', $endpointPolicyRows[0]['@attributes']['uuid'], 'peer preserves existing policy UUID while reconciling by stable policy id');

$same = InterfaceSync::reconcile($r['config'], $payload, fn()=>'unused');
eq(false, $same['changed'], 'idempotent');
eq([], $same['plan']['configure_vlans'], 'idempotent vlan plan');

// Existing dual-node object is adopted only because it has an explicit matching local policy assignment.
$legacy = $source;
$legacy['virtualip']['vip'] = [
    ['interface'=>'customer_net','vhid'=>'77','nosync'=>'1','descr'=>'legacy vip'],
    ['interface'=>'core_wan','vhid'=>'101','nosync'=>'1','descr'=>'core vip'],
];
$legacy['gateways']['gateway_item'] = [
    ['name'=>'customer-v4','interface'=>'customer_net','nosync'=>'1'],
    ['name'=>'WAN_GW','interface'=>'core_wan','nosync'=>'1'],
];
$legacy['filter']['rule'] = [
    ['interface'=>'customer_net','nosync'=>'1','descr'=>'legacy rule'],
    ['interface'=>'core_wan','nosync'=>'1','descr'=>'core rule'],
];
$adopted = InterfaceSync::reconcile($legacy, $payload, fn()=>'adopt-replica');
eq(['customer_net'], $adopted['plan']['adopted_local_assignments'], 'matching explicit local policy adopts legacy object');
eq(['virtualip'=>1,'gateways'=>1,'rules'=>1], $adopted['plan']['adopted_nosync'], 'only managed native records adopted');
eq(false, isset($adopted['config']['virtualip']['vip'][0]['nosync']), 'managed vip nosync cleared');
eq('1', $adopted['config']['virtualip']['vip'][1]['nosync'], 'core vip nosync preserved');
eq(false, isset(InterfaceSync::assignments($adopted['config'])['customer_net']), 'adopted assignment removed from local ownership');
eq('endpoint', InterfaceSync::replicas($adopted['config'])['customer_net']['policy_id'], 'adopted object becomes replica');

$mismatch = $source;
foreach ($mismatch['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['assignments']['assignment'] as &$row) {
    if ($row['interface'] === 'customer_net') $row['policy_id'] = 'core';
}
unset($row);
bad(fn()=>InterfaceSync::reconcile($mismatch, $payload), 'policy mismatch refuses adoption');

$movedPayload = $payload;
$movedPayload['interfaces'][0]['tag'] = 779;
$movedPayload['interfaces'][0]['device'] = 'vlan779';
$movedPayload['interfaces'][0]['description'] = 'Customer network moved';
$movedPayload['prune'] = false;
$moved = InterfaceSync::reconcile($r['config'], $movedPayload, fn()=>'moved-uuid');
eq(['customer_net'], $moved['plan']['reset_interfaces'], 'move resets interface');
eq(['vlan777'], $moved['plan']['destroy_vlans'], 'move destroys old vlan');
eq(['vlan779'], $moved['plan']['configure_vlans'], 'move configures new vlan');
eq('vlan779', $moved['config']['interfaces']['customer_net']['if'], 'move assignment');

$emptyPrepare = $payload;
$emptyPrepare['interfaces'] = [];
$emptyPrepare['prune'] = false;
$held = InterfaceSync::reconcile($r['config'], $emptyPrepare, fn()=>'unused');
eq(false, $held['changed'], 'prepare preserves stale replica');
eq(true, isset($held['config']['interfaces']['customer_net']), 'prepare keeps stale replica');

$emptyPrune = $emptyPrepare;
$emptyPrune['prune'] = true;
$gone = InterfaceSync::reconcile($r['config'], $emptyPrune, fn()=>'unused');
eq(['customer_net'], $gone['plan']['reset_interfaces'], 'prune resets stale replica');
eq(['vlan777'], $gone['plan']['destroy_vlans'], 'prune destroys stale vlan');
eq(false, isset($gone['config']['interfaces']['customer_net']), 'prune removes only peer-owned replica');
eq(false, isset(InterfaceSync::replicas($gone['config'])['customer_net']), 'prune removes replica ownership');

// A local interface with no replica/local-adoption ownership cannot be overwritten even if the identifier is arbitrary.
$collision = base();
$collision['interfaces']['customer_net'] = ['if'=>'vlan777','descr'=>'Local object','enable'=>'1'];
$collision['vlans']['vlan'][] = ['@attributes'=>['uuid'=>'local'],'if'=>'vtnet1','tag'=>'777','pcp'=>'0','proto'=>'','descr'=>'Local object','vlanif'=>'vlan777'];
bad(fn()=>InterfaceSync::reconcile($collision, $payload), 'local ownership collision');

$l3 = $source;
$l3['interfaces']['customer_net']['ipaddr'] = '192.0.2.1';
bad(fn()=>InterfaceSync::buildPayload($l3), 'L3 synchronized scaffold rejected');

bad(fn()=>InterfaceSync::validatePayload([
    'version'=>2,
    'policies'=>$payload['policies'],
    'interfaces'=>[[
        'identifier'=>'anything','policy_id'=>'endpoint','description'=>'bad','tag'=>777,'device'=>'vlan778'
    ]],
    'prune'=>true,
]), 'non canonical device rejected');

$hook = file_get_contents(__DIR__ . '/../src/etc/inc/plugins.inc.d/api_extensions.inc');
eq(true, str_contains($hook, "'id' => 'interface_vlans'"), 'Interfaces sync item registered in standard HA selector');
eq(true, str_contains($hook, "gettext('Interfaces')"), 'Interfaces uses the generic native HA display name');
eq(false, str_contains($hook, 'InterfaceSyncPolicy.sync_marker'), 'custom sync item no longer depends on a fake config section marker');
eq(true, str_contains($hook, "'sync_validate' => 'api_extensions_interface_sync_validate'"), 'interface sync validates before peer mutation');
eq(true, str_contains($hook, "'sync_prepare' => 'api_extensions_interface_sync_prepare'"), 'interface sync prepares peer scaffolding before native sections');
eq(true, str_contains($hook, "'sync_finalize' => 'api_extensions_interface_sync_finalize'"), 'interface sync prunes peer scaffolding after native sections');
eq(true, str_contains($hook, "'id' => 'haproxy_objects'"), 'HAProxy Objects sync item registered in standard HA selector');
eq(true, str_contains($hook, "gettext('HAProxy Objects')"), 'HAProxy Objects uses the native Status/Settings display name');
eq(true, str_contains($hook, "'sync_finalize' => 'api_extensions_haproxy_sync_finalize'"), 'HAProxy object synchronization is a native HA finalizer');

eq(false, file_exists(__DIR__ . '/../src/opnsense/scripts/OPNsense/ApiExtensions/config_sync_push.php'), 'parallel config sync script removed');
eq(false, file_exists(__DIR__ . '/../src/opnsense/mvc/app/controllers/OPNsense/ApiExtensions/Api/InterfaceSyncController.php'), 'parallel interface sync API controller removed');

fwrite(STDOUT, "interface policy sync tests passed\n");
