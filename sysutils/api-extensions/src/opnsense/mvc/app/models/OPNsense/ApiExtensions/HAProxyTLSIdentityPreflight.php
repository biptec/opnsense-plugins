<?php

namespace OPNsense\ApiExtensions;

/**
 * Pure validation helpers for the read-only HAProxy TLS identity preflight.
 */
final class HAProxyTLSIdentityPreflight
{
    public static function dnsLookupSucceeded(int $exitCode, string $stdout): bool
    {
        if ($exitCode !== 0 || trim($stdout) === '') {
            return false;
        }

        foreach (preg_split('/\\R+/', trim($stdout)) ?: [] as $line) {
            $parts = preg_split('/\\s+/', trim($line)) ?: [];
            if ($parts === []) {
                continue;
            }
            $address = trim((string)$parts[0]);
            if (filter_var($address, FILTER_VALIDATE_IP) === false) {
                continue;
            }
            if (!in_array($address, ['127.0.0.1', '::1'], true)) {
                return true;
            }
        }

        return false;
    }

    public static function serviceFindContainsPrincipal(string $output, string $principal): bool
    {
        $principal = trim($principal);
        if ($principal === '') {
            return false;
        }

        if (!preg_match_all(
            '/^\\s*(?:krbprincipalname|principal\\s+alias|principal\\s+name)\\s*:\\s*(.*?)\\s*$/mi',
            $output,
            $matches
        )) {
            return false;
        }

        foreach ($matches[1] as $candidate) {
            if (strcasecmp(trim((string)$candidate), $principal) === 0) {
                return true;
            }
        }

        return false;
    }
}
