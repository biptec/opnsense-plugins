<?php
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/EndpointSync.php';
use OPNsense\ApiExtensions\EndpointSync;

function eq($a, $b, $m) {
    if ($a !== $b) {
        fwrite(STDERR, "$m\nexpected=" . var_export($a, true) . "\nactual=" . var_export($b, true) . "\n");
        exit(1);
    }
}
function bad($fn, $m) {
    try { $fn(); } catch (\InvalidArgumentException $e) { return; }
    fwrite(STDERR, "$m: expected InvalidArgumentException\n"); exit(1);
}
function base() {
    return [
        'hasync' => ['pfsyncinterface' => 'core_ha_control'],
        'interfaces' => [
            'lan' => ['if'=>'vtnet0','descr'=>'Recovery','enable'=>'1'],
            'core_ha_control' => ['if'=>'vlan1901','descr'=>'HA control','enable'=>'1'],
            'core_wan' => ['if'=>'vlan3801','descr'=>'WAN','enable'=>'1'],
        ],
        'vlans' => ['vlan' => [
            ['@attributes'=>['uuid'=>'ha'],'if'=>'vtnet1','tag'=>'1901','pcp'=>'0','proto'=>'','descr'=>'HA control','vlanif'=>'vlan1901'],
            ['@attributes'=>['uuid'=>'wan'],'if'=>'vtnet1','tag'=>'3801','pcp'=>'0','proto'=>'','descr'=>'WAN','vlanif'=>'vlan3801'],
        ]],
    ];
}

$source = base();
$source['interfaces']['ep_demo_0123abcd'] = ['if'=>'vlan777','descr'=>'Endpoint demo','lock'=>'0','enable'=>'1'];
$source['vlans']['vlan'][] = ['@attributes'=>['uuid'=>'source-uuid'],'if'=>'vtnet1','tag'=>'777','pcp'=>'0','proto'=>'','descr'=>'Endpoint demo','vlanif'=>'vlan777'];
$payload = EndpointSync::buildPayload($source);

eq('vtnet1', EndpointSync::localTrunkParent($source), 'local parent');
eq(['version'=>1,'endpoints'=>[[
    'identifier'=>'ep_demo_0123abcd','description'=>'Endpoint demo','tag'=>777,'device'=>'vlan777'
]],'prune'=>true], $payload, 'payload');

$r = EndpointSync::reconcile(base(), $payload, fn()=>'receiver-uuid');
eq(true, $r['changed'], 'create changed');
eq(['vlan777'], $r['plan']['configure_vlans'], 'create vlan plan');
eq(['ep_demo_0123abcd'], $r['plan']['configure_interfaces'], 'create interface plan');
eq([], $r['plan']['reset_interfaces'], 'create reset plan');
eq([], $r['plan']['destroy_vlans'], 'create destroy plan');
eq(['if'=>'vlan777','descr'=>'Endpoint demo','lock'=>'0','enable'=>'1'],
   $r['config']['interfaces']['ep_demo_0123abcd'], 'canonical assignment');
eq('receiver-uuid', $r['config']['vlans']['vlan'][2]['@attributes']['uuid'], 'local uuid');
eq($source['interfaces']['core_wan'], $r['config']['interfaces']['core_wan'], 'core preserved');

$same = EndpointSync::reconcile($r['config'], $payload, fn()=>'unused');
eq(false, $same['changed'], 'idempotent');
eq([], $same['plan']['configure_vlans'], 'idempotent vlan plan');
eq('receiver-uuid', $same['config']['vlans']['vlan'][2]['@attributes']['uuid'], 'uuid stable');

$moved = EndpointSync::reconcile($r['config'], ['version'=>1,'endpoints'=>[[
    'identifier'=>'ep_demo_0123abcd','description'=>'Endpoint demo moved','tag'=>778,'device'=>'vlan778'
]],'prune'=>false], fn()=>'moved-uuid');
eq(true, $moved['changed'], 'device move changed');
eq(['ep_demo_0123abcd'], $moved['plan']['reset_interfaces'], 'device move resets assignment');
eq(['vlan777'], $moved['plan']['destroy_vlans'], 'device move destroys old vlan');
eq(['vlan778'], $moved['plan']['configure_vlans'], 'device move configures new vlan');
eq('vlan778', $moved['config']['interfaces']['ep_demo_0123abcd']['if'], 'device move assignment');
$moveDevices = array_map(fn($v) => $v['vlanif'], $moved['config']['vlans']['vlan']);
eq(false, in_array('vlan777', $moveDevices, true), 'device move removes old vlan record');
eq(true, in_array('vlan778', $moveDevices, true), 'device move adds new vlan record');

$held = EndpointSync::reconcile($r['config'], ['version'=>1,'endpoints'=>[],'prune'=>false], fn()=>'unused');
eq(false, $held['changed'], 'prepare phase preserves stale scaffold');
eq([], $held['plan']['reset_interfaces'], 'prepare phase does not reset stale interfaces');
eq([], $held['plan']['destroy_vlans'], 'prepare phase does not destroy stale vlans');
eq(true, isset($held['config']['interfaces']['ep_demo_0123abcd']), 'prepare phase keeps stale assignment');

$gone = EndpointSync::reconcile($r['config'], ['version'=>1,'endpoints'=>[],'prune'=>true], fn()=>'unused');
eq(['ep_demo_0123abcd'], $gone['plan']['reset_interfaces'], 'delete reset');
eq(['vlan777'], $gone['plan']['destroy_vlans'], 'delete vlan');
eq(false, isset($gone['config']['interfaces']['ep_demo_0123abcd']), 'delete assignment');
eq(2, count($gone['config']['vlans']['vlan']), 'delete only endpoint vlan');

$collision = base();
$collision['interfaces']['service_x'] = ['if'=>'vlan777','descr'=>'Service','enable'=>'1'];
$collision['vlans']['vlan'][] = ['@attributes'=>['uuid'=>'svc'],'if'=>'vtnet1','tag'=>'777','pcp'=>'0','proto'=>'','descr'=>'Service','vlanif'=>'vlan777'];
bad(fn()=>EndpointSync::reconcile($collision, $payload), 'device collision');

$l3 = $source;
$l3['interfaces']['ep_demo_0123abcd']['ipaddr'] = '192.0.2.1';
bad(fn()=>EndpointSync::buildPayload($l3), 'L3 source rejected');

bad(fn()=>EndpointSync::validatePayload(['version'=>1,'endpoints'=>[[
    'identifier'=>'core_wan','description'=>'bad','tag'=>777,'device'=>'vlan777'
]],'prune'=>true]), 'non endpoint id rejected');
bad(fn()=>EndpointSync::validatePayload(['version'=>1,'endpoints'=>[[
    'identifier'=>'ep_demo_0123abcd','description'=>'bad','tag'=>777,'device'=>'vlan778'
]],'prune'=>true]), 'non canonical device rejected');

$pushScript = file_get_contents(__DIR__ . '/../src/opnsense/scripts/OPNsense/ApiExtensions/config_sync_push.php');
eq(false, str_contains($pushScript, 'pre_check_master'), 'static primary config authority must not depend on CARP master state');
eq(true, str_contains($pushScript, 'buildPayload($config, false)'), 'push prepares scaffold before native sync');
eq(true, str_contains($pushScript, 'buildPayload($config, true)'), 'push prunes scaffold after native sync');

fwrite(STDOUT, "endpoint sync tests passed\n");
