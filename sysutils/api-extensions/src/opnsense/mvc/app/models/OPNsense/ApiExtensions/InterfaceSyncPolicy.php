<?php

namespace OPNsense\ApiExtensions;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class InterfaceSyncPolicy extends BaseModel
{
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        $policyReferences = [];
        foreach ($this->shared->policies->policy->iterateItems() as $policy) {
            $id = trim((string)$policy->id->getValue());
            $uuid = trim((string)$policy->getAttribute('uuid'));
            if ($id !== '') {
                $policyReferences[$id] = true;
            }
            if ($uuid !== '') {
                $policyReferences[$uuid] = true;
            }
        }

        foreach ($this->assignments->assignment->iterateItems() as $assignment) {
            $policyId = trim((string)$assignment->policy_id->getValue());
            if ($policyId !== '' && !isset($policyReferences[$policyId])) {
                $messages->appendMessage(new Message(
                    gettext('The selected interface policy does not exist.'),
                    $assignment->__reference . '.policy_id'
                ));
            }
        }

        $haproxyAssignments = [];
        foreach ($this->haproxy_assignments->assignment->iterateItems() as $assignment) {
            $policyId = trim((string)$assignment->policy_id->getValue());
            if ($policyId !== '' && !isset($policyReferences[$policyId])) {
                $messages->appendMessage(new Message(
                    gettext('The selected HA sync policy does not exist.'),
                    $assignment->__reference . '.policy_id'
                ));
            }
            $type = trim((string)$assignment->object_type->getValue());
            $name = trim((string)$assignment->object_name->getValue());
            if ($type !== '' && $name !== '') {
                $key = $type . ':' . $name;
                if (isset($haproxyAssignments[$key])) {
                    $messages->appendMessage(new Message(
                        gettext('Each HAProxy server or backend must have exactly one policy assignment.'),
                        $assignment->__reference . '.object_name'
                    ));
                }
                $haproxyAssignments[$key] = true;
            }
        }

        foreach ($this->haproxy_replicas->replica->iterateItems() as $replica) {
            $policyId = trim((string)$replica->policy_id->getValue());
            if ($policyId !== '' && !isset($policyReferences[$policyId])) {
                $messages->appendMessage(new Message(
                    gettext('The HAProxy replica references a policy that does not exist.'),
                    $replica->__reference . '.policy_id'
                ));
            }
        }

        return $messages;
    }
}
