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

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\SanitizeFilter;

class PackageController extends ApiControllerBase
{
    private function flag(string $value): bool
    {
        return in_array(strtolower(trim($value)), ['1', 'true', 'yes', 'locked'], true);
    }

    public function getAction($package = null): array
    {
        if (!is_string($package) || trim($package) === '') {
            return ['status' => 'failed', 'message' => 'package is required'];
        }

        $requested = trim($package);
        $sanitized = (new SanitizeFilter())->sanitize($requested, 'pkgname');
        if (!is_string($sanitized) || $sanitized === '' || $sanitized !== $requested) {
            return ['status' => 'failed', 'message' => 'invalid package name'];
        }

        $result = trim(
            (new Backend())->configdRun(sprintf('api_extensions package_status %s', $sanitized))
        );
        $fields = explode('|||', $result);
        if (count($fields) === 2 && $fields[0] === 'not-installed') {
            return [
                'status' => 'ok',
                'package' => [
                    'name' => $sanitized,
                    'installed' => false,
                    'provided' => $this->flag($fields[1]),
                    'version' => '',
                    'locked' => false,
                    'repository' => '',
                    'origin' => '',
                ],
            ];
        }

        if (count($fields) !== 6 || $fields[0] !== $sanitized) {
            return ['status' => 'failed', 'message' => 'unable to read local package state'];
        }

        return [
            'status' => 'ok',
            'package' => [
                'name' => $fields[0],
                'installed' => true,
                'provided' => $this->flag($fields[5]),
                'version' => $fields[1],
                'locked' => $this->flag($fields[2]),
                'repository' => $fields[3],
                'origin' => $fields[4],
            ],
        ];
    }
}
