<?php

/*
 * Copyright (C) 2026 Ted Welch <ted.welch@biptec.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
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

namespace OPNsense\ApiExtensions\Api;

use InvalidArgumentException;
use OPNsense\ApiExtensions\ConfigAccess;
use OPNsense\ApiExtensions\Validation;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;


class NtpController extends ApiControllerBase
{
    private const BOOLEAN_FIELDS = [
        'client_mode',
        'kiss_of_death',
        'rate_limiting',
        'deny_modifications',
        'disable_queries',
        'disable_serving',
        'deny_peer_associations',
        'deny_trap_service',
    ];

    private function serverList($config): array
    {
        $hosts = ConfigAccess::spaceList($config->system->timeservers ?? '');
        $flags = [];
        foreach (['noselect', 'prefer', 'iburst', 'ispool'] as $name) {
            $flags[$name] = array_flip(ConfigAccess::spaceList($config->ntpd->{$name} ?? ''));
        }

        $result = [];
        foreach ($hosts as $host) {
            $result[] = [
                'host' => $host,
                'noselect' => isset($flags['noselect'][$host]),
                'prefer' => isset($flags['prefer'][$host]),
                'iburst' => isset($flags['iburst'][$host]),
                'pool' => isset($flags['ispool'][$host]),
            ];
        }
        return $result;
    }

    public function getAction(): array
    {
        $config = Config::getInstance()->object();
        $ntpd = $config->ntpd;

        return ['ntp' => [
            'enabled' => isset($config->system->timeservers) &&
                trim((string)$config->system->timeservers) !== '',
            'servers' => $this->serverList($config),
            'interfaces' => ConfigAccess::commaList($ntpd->interface ?? ''),
            'orphan' => isset($ntpd->orphan) && (string)$ntpd->orphan !== '' ? (int)$ntpd->orphan : 12,
            'max_clock' => isset($ntpd->maxclock) && (string)$ntpd->maxclock !== '' ? (int)$ntpd->maxclock : 10,
            'client_mode' => isset($ntpd->clientmode),
            'kiss_of_death' => !isset($ntpd->kod),
            'rate_limiting' => !isset($ntpd->limited),
            'deny_modifications' => !isset($ntpd->nomodify),
            'disable_queries' => !isset($ntpd->query),
            'disable_serving' => isset($ntpd->noserve),
            'deny_peer_associations' => !isset($ntpd->nopeer),
            'deny_trap_service' => !isset($ntpd->notrap),
        ]];
    }

    private function validateServers($value): array
    {
        if (!is_array($value)) {
            throw new InvalidArgumentException('servers must be a list.');
        }
        $result = [];
        foreach ($value as $index => $server) {
            if (!is_array($server)) {
                throw new InvalidArgumentException(sprintf('servers.%d must be an object.', $index));
            }
            $host = Validation::hostname($server['host'] ?? null, sprintf('servers.%d.host', $index));
            if (isset($result[$host])) {
                throw new InvalidArgumentException(sprintf('servers contains duplicate host %s.', $host));
            }
            $result[$host] = [
                'host' => $host,
                'noselect' => Validation::boolean($server['noselect'] ?? false, 'noselect'),
                'prefer' => Validation::boolean($server['prefer'] ?? false, 'prefer'),
                'iburst' => Validation::boolean($server['iburst'] ?? true, 'iburst'),
                'pool' => Validation::boolean($server['pool'] ?? false, 'pool'),
            ];
        }
        return array_values($result);
    }

    private function setServers($object, $ntpd, array $servers, bool $enabled): void
    {
        foreach (['noselect', 'prefer', 'iburst', 'ispool'] as $name) {
            ConfigAccess::setValue($ntpd, $name, null);
        }
        if (!$enabled) {
            ConfigAccess::setValue($object->system, 'timeservers', null);
            return;
        }

        $hosts = [];
        $flags = ['noselect' => [], 'prefer' => [], 'iburst' => [], 'ispool' => []];
        foreach ($servers as $server) {
            $host = $server['host'];
            $hosts[] = $host;
            foreach (['noselect', 'prefer', 'iburst'] as $flag) {
                if ($server[$flag]) {
                    $flags[$flag][] = $host;
                }
            }
            if ($server['pool']) {
                $flags['ispool'][] = $host;
            }
        }
        ConfigAccess::setValue($object->system, 'timeservers', implode(' ', $hosts));
        foreach ($flags as $name => $hostsWithFlag) {
            ConfigAccess::setValue($ntpd, $name, implode(' ', $hostsWithFlag));
        }
    }

    public function setAction(): array
    {
        $response = ['status' => 'failed', 'validations' => []];
        if (!$this->request->isPost() || !$this->request->hasPost('ntp')) {
            return $response;
        }

        $data = $this->request->getPost('ntp');
        if (!is_array($data)) {
            $response['validations']['ntp'] = 'ntp must be an object.';
            return $response;
        }

        $allowedFields = array_merge(
            ['enabled', 'servers', 'interfaces', 'orphan', 'max_clock'],
            self::BOOLEAN_FIELDS
        );
        foreach (array_keys($data) as $field) {
            if (!in_array($field, $allowedFields, true)) {
                $response['validations'][$field] = sprintf('Unknown field %s.', $field);
            }
        }

        $config = Config::getInstance();
        $current = $config->object();
        $currentNtpd = $current->ntpd;

        try {
            $enabled = Validation::boolean(
                $data['enabled'] ?? (
                    isset($current->system->timeservers) &&
                    trim((string)$current->system->timeservers) !== ''
                ),
                'enabled'
            );
        } catch (InvalidArgumentException $error) {
            $enabled = false;
            $response['validations']['enabled'] = $error->getMessage();
        }

        try {
            $servers = $this->validateServers($data['servers'] ?? $this->serverList($current));
            if ($enabled && empty($servers)) {
                throw new InvalidArgumentException(
                    'servers must contain at least one server when NTP is enabled.'
                );
            }
        } catch (InvalidArgumentException $error) {
            $servers = [];
            $response['validations']['servers'] = $error->getMessage();
        }

        try {
            $interfaces = Validation::interfaces(
                $data['interfaces'] ?? ConfigAccess::commaList($currentNtpd->interface ?? ''),
                ConfigAccess::configuredInterfaces(),
                'interfaces',
                $enabled
            );
        } catch (InvalidArgumentException $error) {
            $interfaces = [];
            $response['validations']['interfaces'] = $error->getMessage();
        }

        $validated = [];
        foreach (self::BOOLEAN_FIELDS as $field) {
            if (!array_key_exists($field, $data)) {
                continue;
            }
            try {
                $validated[$field] = Validation::boolean($data[$field], $field);
            } catch (InvalidArgumentException $error) {
                $response['validations'][$field] = $error->getMessage();
            }
        }
        foreach ([
            'orphan' => [0, 15],
            'max_clock' => [2, 99],
        ] as $field => [$minimum, $maximum]) {
            if (!array_key_exists($field, $data)) {
                continue;
            }
            try {
                $validated[$field] = Validation::integer($data[$field], $field, $minimum, $maximum);
            } catch (InvalidArgumentException $error) {
                $response['validations'][$field] = $error->getMessage();
            }
        }

        if (!empty($response['validations'])) {
            return $response;
        }

        $config->lock();
        $object = $config->object();
        $ntpd = $object->ntpd;
        $this->setServers($object, $ntpd, $servers, $enabled);
        ConfigAccess::setValue($ntpd, 'interface', implode(',', $interfaces));

        foreach ($validated as $field => $value) {
            switch ($field) {
                case 'orphan':
                    ConfigAccess::setValue($ntpd, 'orphan', $value);
                    break;
                case 'max_clock':
                    ConfigAccess::setValue($ntpd, 'maxclock', $value);
                    break;
                case 'client_mode':
                    ConfigAccess::setFlag($ntpd, 'clientmode', $value);
                    break;
                case 'kiss_of_death':
                    ConfigAccess::setFlag($ntpd, 'kod', !$value);
                    break;
                case 'rate_limiting':
                    ConfigAccess::setFlag($ntpd, 'limited', !$value);
                    break;
                case 'deny_modifications':
                    ConfigAccess::setFlag($ntpd, 'nomodify', !$value);
                    break;
                case 'disable_queries':
                    ConfigAccess::setFlag($ntpd, 'query', !$value);
                    break;
                case 'disable_serving':
                    ConfigAccess::setFlag($ntpd, 'noserve', $value);
                    break;
                case 'deny_peer_associations':
                    ConfigAccess::setFlag($ntpd, 'nopeer', !$value);
                    break;
                case 'deny_trap_service':
                    ConfigAccess::setFlag($ntpd, 'notrap', !$value);
                    break;
            }
        }
        $config->save();

        return ['status' => 'ok'];
    }

    public function reconfigureAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        $result = trim((new Backend())->configdRun('api_extensions reconfigure_ntp'));
        return [
            'status' => $result === 'ok' ? 'ok' : 'failed',
            'result' => $result,
        ];
    }
}
