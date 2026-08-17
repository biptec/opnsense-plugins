<?php

namespace OPNsense\ApiExtensions\Migrations;

use OPNsense\Base\BaseModelMigration;

class M1_2_0 extends BaseModelMigration
{
    public function run($model)
    {
        // Before model 1.1.0, checks had no scope and therefore meant global demotion.
        // The 1.2.0 schema defaults new checks to automatic interface discovery, so
        // preserve legacy meaning during the one-time migration.
        foreach ($model->getNodeByReference('checks.check')->iterateItems() as $check) {
            if ((string)$check->scope === 'interface') {
                $check->scope = 'global';
            }
        }
    }
}
