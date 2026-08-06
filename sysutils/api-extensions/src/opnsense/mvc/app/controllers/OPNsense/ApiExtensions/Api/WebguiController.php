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

class WebguiController extends ApiControllerBase
{
    public function getAction(): array
    {
        $config = Config::getInstance()->object();
        $webgui = $config->system->webgui;

        return ['webgui' => [
            'protocol' => (string)$webgui->protocol,
            'port' => isset($webgui->port) && (string)$webgui->port !== ''
                ? (int)$webgui->port
                : ((string)$webgui->protocol === 'https' ? 443 : 80),
            'interfaces' => ConfigAccess::commaList($webgui->interfaces ?? ''),
            'certificate_ref' => (string)($webgui->{'ssl-certref'} ?? ''),
            'session_timeout' => isset($webgui->session_timeout) && (string)$webgui->session_timeout !== ''
                ? (int)$webgui->session_timeout
                : null,
            'hsts' => isset($webgui->{'ssl-hsts'}),
            'disable_http_redirect' => isset($webgui->disablehttpredirect),
            'alternate_hostnames' => ConfigAccess::spaceList($webgui->althostnames ?? ''),
        ]];
    }

    public function setAction(): array
    {
        $response = ['status' => 'failed', 'validations' => []];
        if (!$this->request->isPost() || !$this->request->hasPost('webgui')) {
            return $response;
        }

        $data = $this->request->getPost('webgui');
        if (!is_array($data)) {
            $response['validations']['webgui'] = 'webgui must be an object.';
            return $response;
        }

        $config = Config::getInstance();
        $object = $config->object();
        $webgui = $object->system->webgui;
        $currentProtocol = (string)$webgui->protocol;
        $currentCertificate = (string)($webgui->{'ssl-certref'} ?? '');

        try {
            $protocol = array_key_exists('protocol', $data) ? (string)$data['protocol'] : $currentProtocol;
            if (!in_array($protocol, ['http', 'https'], true)) {
                throw new InvalidArgumentException('protocol must be http or https.');
            }
            $certificate = array_key_exists('certificate_ref', $data)
                ? (string)$data['certificate_ref']
                : $currentCertificate;
            if ($protocol === 'https' && !ConfigAccess::certificateExists($certificate)) {
                throw new InvalidArgumentException('certificate_ref must reference an existing certificate for HTTPS.');
            }
        } catch (InvalidArgumentException $error) {
            $response['validations']['protocol'] = $error->getMessage();
        }

        $validated = [];
        $allowedFields = [
            'protocol',
            'port',
            'interfaces',
            'certificate_ref',
            'session_timeout',
            'hsts',
            'disable_http_redirect',
            'alternate_hostnames',
        ];
        foreach ($data as $field => $value) {
            try {
                switch ($field) {
                    case 'protocol':
                        $validated[$field] = $protocol;
                        break;
                    case 'port':
                        $validated[$field] = Validation::port($value, $field);
                        break;
                    case 'interfaces':
                        $validated[$field] = Validation::interfaces(
                            $value,
                            ConfigAccess::configuredInterfaces(),
                            $field,
                            true
                        );
                        break;
                    case 'certificate_ref':
                        if (!is_string($value)) {
                            throw new InvalidArgumentException('certificate_ref must be a string.');
                        }
                        $validated[$field] = $value;
                        break;
                    case 'session_timeout':
                        $validated[$field] = $value === null
                            ? null
                            : Validation::integer($value, $field, 1, 86400);
                        break;
                    case 'hsts':
                    case 'disable_http_redirect':
                        $validated[$field] = Validation::boolean($value, $field);
                        break;
                    case 'alternate_hostnames':
                        $validated[$field] = Validation::hostnames($value, $field);
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

        if (!empty($response['validations'])) {
            return $response;
        }

        $config->lock();
        $object = $config->object();
        $webgui = $object->system->webgui;
        foreach ($validated as $field => $value) {
            switch ($field) {
                case 'protocol':
                    ConfigAccess::setValue($webgui, 'protocol', $value);
                    break;
                case 'port':
                    ConfigAccess::setValue($webgui, 'port', $value);
                    break;
                case 'interfaces':
                    ConfigAccess::setValue($webgui, 'interfaces', implode(',', $value));
                    break;
                case 'certificate_ref':
                    ConfigAccess::setValue($webgui, 'ssl-certref', $value);
                    break;
                case 'session_timeout':
                    ConfigAccess::setValue($webgui, 'session_timeout', $value);
                    break;
                case 'hsts':
                    ConfigAccess::setFlag($webgui, 'ssl-hsts', $value);
                    break;
                case 'disable_http_redirect':
                    ConfigAccess::setFlag($webgui, 'disablehttpredirect', $value);
                    break;
                case 'alternate_hostnames':
                    ConfigAccess::setValue($webgui, 'althostnames', implode(' ', $value));
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
        $message = trim((new Backend())->configdRun('webgui restart 2', true));
        return [
            'status' => ConfigAccess::commandSucceeded($message, null) ? 'ok' : 'failed',
            'msg_uuid' => $message,
        ];
    }
}
