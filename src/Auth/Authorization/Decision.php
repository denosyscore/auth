<?php

declare(strict_types=1);

namespace Denosys\Auth\Authorization;

enum Decision: string
{
    /**
     * The voter grants access.
     */
    case ALLOW = 'allow';

    /**
     * The voter denies access.
     */
    case DENY = 'deny';

    /**
     * The voter abstains (has no opinion).
     * This is used when the voter doesn't handle this type of check.
     */
    case ABSTAIN = 'abstain';
}
