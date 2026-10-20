<?php

/*
 * Copyright (C) 2018 Franco Fichtner <franco@opnsense.org>
 * Copyright (C) 2017 Fabian Franz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

function frr_enabled()
{
    $model = new \OPNsense\Quagga\General();
    return (string)$model->enabled == '1';
}

function frr_carp_enabled()
{
    $model = new \OPNsense\Quagga\General();
    return (string)$model->enabled == '1' &&
        (string)$model->enablecarp == '1';
}

function frr_configure()
{
    return [
        'staticroutes' => ['frr_staticroutes_configure'],
    ];
}

function frr_staticroutes_configure($verbose = false)
{
    if (!frr_enabled()) {
        return;
    }

    service_log('Reloading FRR endpoint static-route exports...', $verbose);
    configd_run('template reload OPNsense/Quagga');
    configd_run('quagga reload');
    service_log("done.\n", $verbose);
}

function frr_route_lookup($address, $family)
{
    $output = shell_safe('/sbin/route -n get -%s %s', [$family, $address]);
    if (!is_string($output) || $output === '') {
        return null;
    }

    $route = ['gateway' => '', 'interface' => ''];
    foreach (preg_split('/\r?\n/', $output) as $line) {
        if (preg_match('/^\s*(gateway|interface):\s*(\S+)/', $line, $matches)) {
            $route[$matches[1]] = $matches[2];
        }
    }

    return $route['interface'] !== '' ? $route : null;
}

function frr_carp_staticroutes_reconcile($subsystem, $type)
{
    global $config;

    if (!in_array($type, ['MASTER', 'BACKUP'], true) ||
        !preg_match('/^[0-9]+@([A-Za-z0-9_.:-]+)$/D', (string)$subsystem, $matches)) {
        return;
    }

    $device = $matches[1];
    $interface = null;
    foreach (($config['interfaces'] ?? []) as $identifier => $ifcfg) {
        if (is_array($ifcfg) && ($ifcfg['if'] ?? '') === $device) {
            $interface = $identifier;
            break;
        }
    }
    if ($interface === null) {
        return;
    }

    try {
        $assignments = \OPNsense\ApiExtensions\InterfaceSync::assignments($config);
        $policies = \OPNsense\ApiExtensions\InterfaceSync::policies($config);
    } catch (\Throwable $e) {
        log_msg(sprintf(
            'FRR CARP static-route reconcile skipped for %s: %s',
            $interface,
            $e->getMessage()
        ), LOG_WARNING);
        return;
    }

    $assignment = $assignments[$interface] ?? null;
    $policy = is_array($assignment) ? ($policies[$assignment['policy_id']] ?? null) : null;
    if (!is_array($policy) || empty($policy['synchronize'])) {
        return;
    }

    log_msg(sprintf(
        'FRR CARP %s on synchronized interface %s; reconciling owned static routes',
        $type,
        $interface
    ), LOG_NOTICE);

    $gateways = (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(false, true);
    foreach (get_staticroutes(false) as $route) {
        $gateway = $gateways[$route['gateway']] ?? null;
        if (!is_array($gateway) || ($gateway['interface'] ?? '') !== $interface) {
            continue;
        }

        $network = $route['network'] ?? '';
        if (is_subnetv4($network)) {
            $family = 'inet';
        } elseif (is_subnetv6($network)) {
            $family = 'inet6';
        } else {
            continue;
        }

        if (!empty($route['disabled'])) {
            mwexecfm('/sbin/route delete -%s %s', [$family, $network]);
            continue;
        }

        $gatewayip = $gateway['gateway'] ?? '';
        if (!is_ipaddr($gatewayip)) {
            continue;
        }

        $gateway_interface = $gateway['if'] ?? '';
        if ($type === 'BACKUP') {
            // ConnectedCarpEventHandler runs first and resolves this endpoint
            // gateway through the current OSPF peer.  Use that peer next-hop
            // directly for dependent routed destinations: FreeBSD otherwise
            // keeps the native static route associated with the local CARP
            // interface even while the gateway prefix itself is remote.
            $lookup = frr_route_lookup($gatewayip, $family);
            if (!is_array($lookup) ||
                empty($lookup['gateway']) ||
                empty($lookup['interface']) ||
                $lookup['interface'] === $gateway_interface) {
                // A local-looking route on BACKUP is never a valid fallback.
                // Remove our owned destination rather than blackholing it on
                // the non-owning endpoint interface.
                mwexecfm('/sbin/route delete -%s %s', [$family, $network]);
                continue;
            }
            $gatewayip = $lookup['gateway'];
            $gateway_interface = $lookup['interface'];
        }

        if (is_linklocal(strtok($gatewayip, '%')) && strpos($gatewayip, '%') === false && $gateway_interface !== '') {
            $gatewayip .= '%' . $gateway_interface;
        }

        // RTM_CHANGE is atomic and avoids a delete/add race with an existing
        // dynamic route.  Pass route operands as arguments instead of embedding
        // them in a printf-style format string; scoped IPv6 gateways contain
        // a literal '%' (for example %vlan3803).
        if ($family === 'inet' && is_ipaddrv6(strtok($gatewayip, '%'))) {
            $result = mwexecfm(
                '/sbin/route change -%s %s -inet6 %s',
                [$family, $network, $gatewayip]
            );
            if ($result !== 0) {
                mwexecfm('/sbin/route add -%s %s -inet6 %s', [$family, $network, $gatewayip]);
            }
        } else {
            $result = mwexecfm('/sbin/route change -%s %s %s', [$family, $network, $gatewayip]);
            if ($result !== 0) {
                mwexecfm('/sbin/route add -%s %s %s', [$family, $network, $gatewayip]);
            }
        }
    }
}

function frr_firewall($fw)
{
    global $config;
    if (empty((string)(new \OPNsense\Quagga\General())->fwrules)) {
        // automatic rules disabled
        return;
    }
    $ospf = new \OPNsense\Quagga\OSPF();

    if ((string)$ospf->enabled == '1') {
        $ospf_default = [
            'ipprotocol'     => 'inet',
            'protocol'       => 'ospf',
            'statetype'      => 'keep',
            'type'           => 'pass',
            'disablereplyto' => 1,
            'quick'          => true,
            'log'            => !isset($config['syslog']['nologdefaultpass']),
            '#ref'           => 'ui/quagga/general/index',
        ];
        foreach ($ospf->networks->network->iterateItems() as $network) {
            if ((string)$network->enabled == '1') {
                $fw->registerFilterRule(
                    1, /* priority */
                    [
                        'descr'          => 'Pass OSPF (autogenerated)',
                        'from'           => $network->ipaddr . '/' . $network->netmask,
                        'to'             => '224.0.0.0/24',
                        'direction'      => 'in'
                    ],
                    $ospf_default
                );
                $fw->registerFilterRule(
                    1,
                    [
                        'descr'          => 'Pass OSPF UNICAST (autogenerated)',
                        'from'           => $network->ipaddr . '/' . $network->netmask,
                        'to'             => '(self)',
                        'direction'      => 'in'
                    ],
                    $ospf_default
                );
                $fw->registerFilterRule(
                    1,
                    [
                        'descr'          => 'Pass OSPF (autogenerated)',
                        'from'           => '(self)',
                        'to'             => '224.0.0.0/24',
                        'direction'      => 'out'
                    ],
                    $ospf_default
                );
                $fw->registerFilterRule(
                    1,
                    [
                        'descr'          => 'Pass OSPF UNICAST (autogenerated)',
                        'from'           => '(self)',
                        'to'             => $network->ipaddr . '/' . $network->netmask,
                        'direction'      => 'out',
                    ],
                    $ospf_default
                );
            }
        }
    }

    $ospf6 = new \OPNsense\Quagga\OSPF6();

    if ((string)$ospf6->enabled == '1') {
        $ospf6_default = [
            'ipprotocol'     => 'inet6',
            'protocol'       => 'ospf',
            'statetype'      => 'keep',
            'type'           => 'pass',
            'disablereplyto' => 1,
            'quick'          => true,
            'log'            => !isset($config['syslog']['nologdefaultpass']),
            '#ref'           => 'ui/quagga/general/index',
        ];

        foreach ($ospf6->interfaces->interface->iterateItems() as $interface) {
            if ((string)$interface->enabled == '1') {
                $fw->registerFilterRule(
                    1, /* priority */
                    [
                        'interface'      => (string)$interface->interfacename,
                        'descr'          => 'Pass OSPF6 MULTICAST (autogenerated)',
                        'from'           => 'fe80::0/10',
                        'to'             => 'ff02::5/128',
                        'direction'      => 'in'
                    ],
                    $ospf6_default
                );
                $fw->registerFilterRule(
                    1, /* priority */
                    [
                        'interface'      => (string)$interface->interfacename,
                        'descr'          => 'Pass OSPF6 MULTICAST DR (autogenerated)',
                        'from'           => 'fe80::0/10',
                        'to'             => 'ff02::6/128',
                        'direction'      => 'in'
                    ],
                    $ospf6_default
                );
                $fw->registerFilterRule(
                    1,
                    [
                        'interface'      => (string)$interface->interfacename,
                        'descr'          => 'Pass OSPF6 UNICAST (autogenerated)',
                        'from'           => 'fe80::0/10',
                        'to'             => '(self)',
                        'direction'      => 'in'
                    ],
                    $ospf6_default
                );
                $fw->registerFilterRule(
                    1,
                    [
                        'interface'      => (string)$interface->interfacename,
                        'descr'          => 'Pass OSPF6 MULTICAST (autogenerated)',
                        'from'           => '(self)',
                        'to'             => 'ff02::5/128',
                        'direction'      => 'out'
                    ],
                    $ospf6_default
                );
                $fw->registerFilterRule(
                    1,
                    [
                        'interface'      => (string)$interface->interfacename,
                        'descr'          => 'Pass OSPF6 MULTICAST DR (autogenerated)',
                        'from'           => '(self)',
                        'to'             => 'ff02::6/128',
                        'direction'      => 'out'
                    ],
                    $ospf6_default
                );
                $fw->registerFilterRule(
                    1,
                    [
                        'interface'      => (string)$interface->interfacename,
                        'descr'          => 'Pass OSPF6 UNICAST (autogenerated)',
                        'from'           => '(self)',
                        'to'             => 'fe80::0/10',
                        'direction'      => 'out'
                    ],
                    $ospf6_default
                );
            }
        }
    }
}

function frr_services()
{
    $services = array();

    if (frr_enabled()) {
        $services[] = array(
            'description' => gettext('FRRouting Daemon'),
            'configd' => array(
                'restart' => array('quagga restart'),
                'start' => array('quagga start'),
                'stop' => array('quagga stop'),
            ),
            'name' => 'frr',
            'pidfile' => '/var/run/frr/zebra.pid'
        );
    }

    return $services;
}

function frr_xmlrpc_sync()
{
    $result = array();
    $result['id'] = 'quagga';
    $result['section'] = 'OPNsense.quagga';
    $result['description'] = gettext('FRR');
    $result['services'] = ['frr'];
    return array($result);
}
