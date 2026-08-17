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
            if ($check->scope->getValue() === 'vhid') {
                $vhid = (int)$check->vhid->getValue();
                if ($vhid < 1 || $vhid > 255) {
                    $messages->appendMessage(new Message(
                        gettext('VHID must be between 1 and 255 when scope is Specific VHID.'),
                        $check->__reference . '.vhid'
                    ));
                }
            }
        }
        return $messages;
    }
}
