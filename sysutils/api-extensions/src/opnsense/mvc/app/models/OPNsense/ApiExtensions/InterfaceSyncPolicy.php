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

        return $messages;
    }
}
