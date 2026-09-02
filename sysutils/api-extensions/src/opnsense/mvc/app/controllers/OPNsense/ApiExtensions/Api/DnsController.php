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

class DnsController extends ApiControllerBase
{
    private function serverList($system): array
    {
        $result = [];
        if (!isset($system->dnsserver)) {
            return $result;
        }
        foreach ($system->dnsserver as $server) {
            $value = trim((string)$server);
            if ($value !== '') {
                $result[] = $value;
            }
        }
        return $result;
    }

    private function validateServers($value): array
    {
        if (!is_array($value)) {
            throw new InvalidArgumentException('servers must be a list.');
        }
        if (count($value) > 8) {
            throw new InvalidArgumentException('servers may contain at most 8 addresses.');
        }

        $result = [];
        foreach ($value as $index => $server) {
            if (!is_string($server) || filter_var($server, FILTER_VALIDATE_IP) === false) {
                throw new InvalidArgumentException(
                    sprintf('servers.%d must be an IPv4 or IPv6 address.', $index)
                );
            }
            if (isset($result[$server])) {
                throw new InvalidArgumentException(sprintf('servers contains duplicate address %s.', $server));
            }
            $result[$server] = $server;
        }
        return array_values($result);
    }

    public function getAction(): array
    {
        $config = Config::getInstance()->object();
        $system = $config->system;

        return ['dns' => [
            'servers' => $this->serverList($system),
            'allow_override' => isset($system->dnsallowoverride) &&
                (string)$system->dnsallowoverride !== '' &&
                (string)$system->dnsallowoverride !== '0',
            'use_local_service' => !isset($system->dnslocalhost),
        ]];
    }

    public function setAction(): array
    {
        $response = ['status' => 'failed', 'validations' => []];
        if (!$this->request->isPost() || !$this->request->hasPost('dns')) {
            return $response;
        }

        $data = $this->request->getPost('dns');
        if (!is_array($data)) {
            $response['validations']['dns'] = 'dns must be an object.';
            return $response;
        }

        $allowedFields = ['servers', 'allow_override', 'use_local_service'];
        foreach (array_keys($data) as $field) {
            if (!in_array($field, $allowedFields, true)) {
                $response['validations'][$field] = sprintf('Unknown field %s.', $field);
            }
        }

        $config = Config::getInstance();
        $current = $config->object()->system;

        try {
            $servers = $this->validateServers($data['servers'] ?? $this->serverList($current));
        } catch (InvalidArgumentException $error) {
            $servers = [];
            $response['validations']['servers'] = $error->getMessage();
        }

        try {
            $allowOverride = Validation::boolean(
                $data['allow_override'] ?? (
                    isset($current->dnsallowoverride) &&
                    (string)$current->dnsallowoverride !== '' &&
                    (string)$current->dnsallowoverride !== '0'
                ),
                'allow_override'
            );
        } catch (InvalidArgumentException $error) {
            $allowOverride = false;
            $response['validations']['allow_override'] = $error->getMessage();
        }

        try {
            $useLocalService = Validation::boolean(
                $data['use_local_service'] ?? !isset($current->dnslocalhost),
                'use_local_service'
            );
        } catch (InvalidArgumentException $error) {
            $useLocalService = true;
            $response['validations']['use_local_service'] = $error->getMessage();
        }

        if (!empty($response['validations'])) {
            return $response;
        }

        $config->lock();
        $system = $config->object()->system;

        if (isset($system->dnsserver)) {
            unset($system->dnsserver);
        }
        foreach ($servers as $server) {
            $system->addChild('dnsserver', $server);
        }

        for ($index = 1; $index <= 8; $index++) {
            ConfigAccess::setValue($system, sprintf('dns%dgw', $index), 'none');
        }
        ConfigAccess::setFlag($system, 'dnsallowoverride', $allowOverride);
        ConfigAccess::setFlag($system, 'dnslocalhost', !$useLocalService);
        $config->save();

        return ['status' => 'ok'];
    }

    public function reconfigureAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        $result = trim((new Backend())->configdRun('api_extensions reconfigure_resolver'));
        return [
            'status' => $result === 'ok' ? 'ok' : 'failed',
            'result' => $result,
        ];
    }
}
