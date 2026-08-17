<?php

namespace OPNsense\ApiExtensions;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class CarpHealth extends BaseModel
{
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        foreach ($this->checks->check->iterateItems() as $check) {
            if (!$validateFullModel && !$check->isFieldChanged()) {
                continue;
            }
            $scope = $check->scope->getValue();
            if ($scope === 'vhid') {
                $vhid = (int)$check->vhid->getValue();
                if ($vhid < 1 || $vhid > 255) {
                    $messages->appendMessage(new Message(gettext('VHID must be between 1 and 255 when scope is Specific VHID.'), $check->__reference . '.vhid'));
                }
            } elseif ($scope === 'vhid_group') {
                $targetsValue = $check->vhid_targets->getValue();
                $targets = is_array($targetsValue)
                    ? array_filter(array_map('trim', $targetsValue))
                    : array_filter(array_map('trim', explode(',', (string)$targetsValue)));
                if (count($targets) === 0) {
                    $messages->appendMessage(new Message(gettext('At least one interface:VHID target is required for VHID target group scope.'), $check->__reference . '.vhid_targets'));
                }
                foreach ($targets as $target) {
                    if (!preg_match('/^[0-9A-Za-z._-]+:([0-9]{1,3})$/', $target, $matches) || (int)$matches[1] < 1 || (int)$matches[1] > 255) {
                        $messages->appendMessage(new Message(gettext('VHID targets must use interface:VHID with VHID between 1 and 255.'), $check->__reference . '.vhid_targets'));
                        break;
                    }
                }
            }
            foreach ([
                ['fallback_ipv4_target', 'fallback_ipv4_gateway', FILTER_FLAG_IPV4, 'IPv4'],
                ['fallback_ipv6_target', 'fallback_ipv6_gateway', FILTER_FLAG_IPV6, 'IPv6'],
            ] as $route) {
                [$targetField, $gatewayField, $flag, $label] = $route;
                $target = trim((string)$check->{$targetField}->getValue());
                $gateway = trim((string)$check->{$gatewayField}->getValue());
                if (($target === '') !== ($gateway === '')) {
                    $messages->appendMessage(new Message(sprintf(gettext('%s fallback target and gateway must be configured together.'), $label), $check->__reference . '.' . $targetField));
                    continue;
                }
                if ($target !== '' && filter_var($target, FILTER_VALIDATE_IP, $flag) === false) {
                    $messages->appendMessage(new Message(sprintf(gettext('%s fallback target is not a valid address.'), $label), $check->__reference . '.' . $targetField));
                }
                if ($gateway !== '' && filter_var($gateway, FILTER_VALIDATE_IP, $flag) === false) {
                    $messages->appendMessage(new Message(sprintf(gettext('%s fallback gateway is not a valid address.'), $label), $check->__reference . '.' . $gatewayField));
                }
            }
            foreach ([
                ['fallback_ipv4_default_gateway', FILTER_FLAG_IPV4, 'IPv4', 'fallback'],
                ['fallback_ipv6_default_gateway', FILTER_FLAG_IPV6, 'IPv6', 'fallback'],
                ['backup_ipv4_default_gateway', FILTER_FLAG_IPV4, 'IPv4', 'BACKUP'],
                ['backup_ipv6_default_gateway', FILTER_FLAG_IPV6, 'IPv6', 'BACKUP'],
            ] as $defaultRoute) {
                [$gatewayField, $flag, $label, $routeMode] = $defaultRoute;
                $gateway = trim((string)$check->{$gatewayField}->getValue());
                if ($gateway !== '' && filter_var($gateway, FILTER_VALIDATE_IP, $flag) === false) {
                    $messages->appendMessage(new Message(sprintf(gettext('%s %s default gateway is not a valid address.'), $label, $routeMode), $check->__reference . '.' . $gatewayField));
                }
                if ($gateway !== '' && $scope === 'global') {
                    $messages->appendMessage(new Message(gettext('Conditional default routing requires a CARP-scoped health check.'), $check->__reference . '.' . $gatewayField));
                }
            }
            foreach ([
                ['fallback_ipv4_default_gateway', 'backup_ipv4_default_gateway', 'IPv4'],
                ['fallback_ipv6_default_gateway', 'backup_ipv6_default_gateway', 'IPv6'],
            ] as $exclusiveRoute) {
                [$fallbackField, $backupField, $label] = $exclusiveRoute;
                if (trim((string)$check->{$fallbackField}->getValue()) !== '' && trim((string)$check->{$backupField}->getValue()) !== '') {
                    $messages->appendMessage(new Message(sprintf(gettext('%s fallback and BACKUP default gateways are mutually exclusive.'), $label), $check->__reference . '.' . $backupField));
                }
            }
        }
        return $messages;
    }
}
