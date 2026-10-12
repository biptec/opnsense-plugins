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
        $checks = $model->getNodeByReference('checks.check');
        if ($checks === null) {
            // Fresh Golden/NoCloud configs have no existing checks to migrate.
            return;
        }
        foreach ($checks->iterateItems() as $check) {
            if ((string)$check->scope === 'interface') {
                $check->scope = 'global';
            }
        }
    }
}
