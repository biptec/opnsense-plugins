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

use InvalidArgumentException;

class Validation
{
    public static function boolean($value, string $field): bool
    {
        if (!is_bool($value)) {
            throw new InvalidArgumentException(sprintf('%s must be a boolean.', $field));
        }
        return $value;
    }

    public static function port($value, string $field): int
    {
        if (filter_var($value, FILTER_VALIDATE_INT) === false) {
            throw new InvalidArgumentException(sprintf('%s must be an integer.', $field));
        }
        $value = (int)$value;
        if ($value < 1 || $value > 65535) {
            throw new InvalidArgumentException(sprintf('%s must be between 1 and 65535.', $field));
        }
        return $value;
    }

    public static function integer($value, string $field, int $minimum, int $maximum): int
    {
        if (filter_var($value, FILTER_VALIDATE_INT) === false) {
            throw new InvalidArgumentException(sprintf('%s must be an integer.', $field));
        }
        $value = (int)$value;
        if ($value < $minimum || $value > $maximum) {
            throw new InvalidArgumentException(
                sprintf('%s must be between %d and %d.', $field, $minimum, $maximum)
            );
        }
        return $value;
    }

    public static function interfaces($value, array $available, string $field, bool $required = true): array
    {
        if (!is_array($value)) {
            throw new InvalidArgumentException(sprintf('%s must be a list.', $field));
        }
        $result = [];
        foreach ($value as $interface) {
            if (!is_string($interface) || $interface === '') {
                throw new InvalidArgumentException(sprintf('%s contains an invalid interface.', $field));
            }
            if (!array_key_exists($interface, $available)) {
                throw new InvalidArgumentException(
                    sprintf('%s contains unknown interface %s.', $field, $interface)
                );
            }
            $result[$interface] = $interface;
        }
        if ($required && empty($result)) {
            throw new InvalidArgumentException(sprintf('%s must contain at least one interface.', $field));
        }
        return array_values($result);
    }

    public static function hostname($value, string $field): string
    {
        if (!is_string($value) || $value === '' || strlen($value) > 253) {
            throw new InvalidArgumentException(sprintf('%s must be a valid hostname or IP address.', $field));
        }
        if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
            return $value;
        }
        $labels = explode('.', rtrim($value, '.'));
        foreach ($labels as $label) {
            if ($label === '' || strlen($label) > 63 ||
                !preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/', $label)) {
                throw new InvalidArgumentException(
                    sprintf('%s must be a valid hostname or IP address.', $field)
                );
            }
        }
        return $value;
    }

    public static function hostnames($value, string $field): array
    {
        if (!is_array($value)) {
            throw new InvalidArgumentException(sprintf('%s must be a list.', $field));
        }
        $result = [];
        foreach ($value as $hostname) {
            $validated = self::hostname($hostname, $field);
            $result[$validated] = $validated;
        }
        return array_values($result);
    }
}
