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

require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/Validation.php';

use InvalidArgumentException;
use OPNsense\ApiExtensions\Validation;

function assertSameValue($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, sprintf("%s: expected %s, got %s\n", $message, var_export($expected, true), var_export($actual, true)));
        exit(1);
    }
}

function assertInvalid(callable $callable, string $message): void
{
    try {
        $callable();
    } catch (InvalidArgumentException $error) {
        return;
    }
    fwrite(STDERR, $message . ": expected InvalidArgumentException\n");
    exit(1);
}

assertSameValue(true, Validation::boolean(true, 'enabled'), 'boolean true');
assertInvalid(fn() => Validation::boolean('true', 'enabled'), 'boolean string rejected');
assertSameValue(443, Validation::port(443, 'port'), 'valid port');
assertInvalid(fn() => Validation::port(0, 'port'), 'zero port rejected');
assertInvalid(fn() => Validation::port(65536, 'port'), 'large port rejected');
assertSameValue(12, Validation::integer(12, 'orphan', 0, 15), 'bounded integer');
assertInvalid(fn() => Validation::integer(16, 'orphan', 0, 15), 'out of range integer rejected');

$available = ['lan' => 'Management', 'opt1' => 'Service'];
assertSameValue(['lan', 'opt1'], Validation::interfaces(['lan', 'opt1', 'lan'], $available, 'interfaces'), 'interface normalization');
assertInvalid(fn() => Validation::interfaces([], $available, 'interfaces'), 'empty interface list rejected');
assertInvalid(fn() => Validation::interfaces(['wan'], $available, 'interfaces'), 'unknown interface rejected');
assertSameValue([], Validation::interfaces([], $available, 'interfaces', false), 'optional empty interface list');

assertSameValue('time.example.net', Validation::hostname('time.example.net', 'host'), 'hostname');
assertSameValue('192.0.2.1', Validation::hostname('192.0.2.1', 'host'), 'IPv4 address');
assertSameValue('2001:db8::1', Validation::hostname('2001:db8::1', 'host'), 'IPv6 address');
assertInvalid(fn() => Validation::hostname('bad_host.example', 'host'), 'invalid hostname rejected');
assertSameValue(
    ['router.example.net', 'router.internal'],
    Validation::hostnames(['router.example.net', 'router.internal', 'router.example.net'], 'hostnames'),
    'hostname list normalization'
);

fwrite(STDOUT, "validation tests passed\n");
