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

class SshController extends ApiControllerBase
{
    public function getAction(): array
    {
        $config = Config::getInstance()->object();
        $ssh = $config->system->ssh;

        return ['ssh' => [
            'enabled' => isset($ssh->enabled),
            'port' => isset($ssh->port) && (string)$ssh->port !== '' ? (int)$ssh->port : 22,
            'interfaces' => ConfigAccess::commaList($ssh->interfaces ?? ''),
            'password_authentication' => isset($ssh->passwordauth),
            'permit_root_login' => isset($ssh->permitrootlogin),
        ]];
    }

    public function setAction(): array
    {
        $response = ['status' => 'failed', 'validations' => []];
        if (!$this->request->isPost() || !$this->request->hasPost('ssh')) {
            return $response;
        }

        $data = $this->request->getPost('ssh');
        if (!is_array($data)) {
            $response['validations']['ssh'] = 'ssh must be an object.';
            return $response;
        }

        $config = Config::getInstance();
        $object = $config->object();
        $ssh = $object->system->ssh;
        $enabled = array_key_exists('enabled', $data)
            ? $data['enabled']
            : isset($ssh->enabled);
        $interfaces = array_key_exists('interfaces', $data)
            ? $data['interfaces']
            : ConfigAccess::commaList($ssh->interfaces ?? '');

        $validated = [];
        $allowedFields = [
            'enabled',
            'port',
            'interfaces',
            'password_authentication',
            'permit_root_login',
        ];
        foreach ($data as $field => $value) {
            try {
                switch ($field) {
                    case 'enabled':
                    case 'password_authentication':
                    case 'permit_root_login':
                        $validated[$field] = Validation::boolean($value, $field);
                        break;
                    case 'port':
                        $validated[$field] = Validation::port($value, $field);
                        break;
                    case 'interfaces':
                        $validated[$field] = Validation::interfaces(
                            $value,
                            ConfigAccess::configuredInterfaces(),
                            $field,
                            $enabled === true
                        );
                        break;
                    default:
                        if (!in_array($field, $allowedFields, true)) {
                            throw new InvalidArgumentException(sprintf('Unknown field %s.', $field));
                        }
                        break;
                }
            } catch (InvalidArgumentException $error) {
                $response['validations'][$field] = $error->getMessage();
            }
        }

        try {
            $enabled = Validation::boolean($enabled, 'enabled');
            Validation::interfaces(
                $interfaces,
                ConfigAccess::configuredInterfaces(),
                'interfaces',
                $enabled
            );
        } catch (InvalidArgumentException $error) {
            $response['validations']['interfaces'] = $error->getMessage();
        }

        if (!empty($response['validations'])) {
            return $response;
        }

        $config->lock();
        $object = $config->object();
        $ssh = $object->system->ssh;
        $ssh->noauto = '1';
        foreach ($validated as $field => $value) {
            switch ($field) {
                case 'enabled':
                    if ($value) {
                        $ssh->enabled = 'enabled';
                    } elseif (isset($ssh->enabled)) {
                        unset($ssh->enabled);
                    }
                    break;
                case 'port':
                    ConfigAccess::setValue($ssh, 'port', $value);
                    break;
                case 'interfaces':
                    ConfigAccess::setValue($ssh, 'interfaces', implode(',', $value));
                    break;
                case 'password_authentication':
                    ConfigAccess::setFlag($ssh, 'passwordauth', $value);
                    break;
                case 'permit_root_login':
                    ConfigAccess::setFlag($ssh, 'permitrootlogin', $value);
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
        $result = trim((new Backend())->configdRun('openssh restart'));
        return [
            'status' => ConfigAccess::commandSucceeded($result) ? 'ok' : 'failed',
            'result' => $result,
        ];
    }
}
