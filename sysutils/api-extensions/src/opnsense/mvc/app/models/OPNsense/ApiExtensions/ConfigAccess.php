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

namespace OPNsense\ApiExtensions;

use OPNsense\Core\Config;

class ConfigAccess
{
    public static function configuredInterfaces(): array
    {
        $result = [];
        $config = Config::getInstance()->object();
        if (!isset($config->interfaces)) {
            return $result;
        }
        foreach ($config->interfaces->children() as $name => $node) {
            $result[(string)$name] = isset($node->descr) && (string)$node->descr !== ''
                ? (string)$node->descr
                : (string)$name;
        }
        return $result;
    }

    public static function commaList($value): array
    {
        $value = trim((string)$value);
        return $value === '' ? [] : array_values(array_filter(explode(',', $value), 'strlen'));
    }

    public static function spaceList($value): array
    {
        $value = trim((string)$value);
        return $value === '' ? [] : preg_split('/\s+/', $value);
    }

    public static function setValue($node, string $name, $value): void
    {
        if ($value === null || $value === '') {
            if (isset($node->{$name})) {
                unset($node->{$name});
            }
            return;
        }
        $node->{$name} = (string)$value;
    }

    public static function setFlag($node, string $name, bool $enabled): void
    {
        if ($enabled) {
            $node->{$name} = '1';
        } elseif (isset($node->{$name})) {
            unset($node->{$name});
        }
    }

    public static function commandSucceeded($result, ?string $expected = 'OK'): bool
    {
        if (!is_string($result)) {
            return false;
        }
        $result = trim($result);
        if ($result === '') {
            return false;
        }
        return $expected === null || strcasecmp($result, $expected) === 0;
    }

    public static function certificateSupportsServerAuth(string $reference): bool
    {
        if ($reference === '') {
            return false;
        }
        $config = Config::getInstance()->object();
        if (!isset($config->cert)) {
            return false;
        }
        foreach ($config->cert as $certificate) {
            if (isset($certificate->refid) && (string)$certificate->refid === $reference) {
                return self::encodedCertificateSupportsServerAuth((string)($certificate->crt ?? ''));
            }
        }
        return false;
    }

    public static function encodedCertificateSupportsServerAuth(string $encoded): bool
    {
        $certificate = base64_decode($encoded, true);
        if ($certificate === false || $certificate === '') {
            return false;
        }
        $details = @openssl_x509_parse($certificate);
        return is_array($details) && self::parsedCertificateSupportsServerAuth($details);
    }

    public static function parsedCertificateSupportsServerAuth(array $details): bool
    {
        $extendedKeyUsage = (string)($details['extensions']['extendedKeyUsage'] ?? '');
        $purposes = array_map('trim', explode(',', $extendedKeyUsage));
        return in_array('TLS Web Server Authentication', $purposes, true);
    }
}
