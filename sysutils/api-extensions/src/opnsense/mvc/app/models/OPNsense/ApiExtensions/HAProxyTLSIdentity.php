<?php

namespace OPNsense\ApiExtensions;

use OPNsense\Base\BaseModel;

/**
 * Persisted non-secret HAProxy TLS identity registrations.
 *
 * Private keys and certificate bodies are intentionally not part of this
 * model. They are materialized locally on each Router.
 */
class HAProxyTLSIdentity extends BaseModel
{
}
