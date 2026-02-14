<?php

declare(strict_types=1);

namespace Denosys\Auth\Authorization;

enum DecisionStrategy: string
{
    /**
     * At least one voter must ALLOW, no voters can DENY.
     */
    case AFFIRMATIVE = 'affirmative';

    /**
     * All voters must ALLOW or ABSTAIN (no DENY).
     */
    case UNANIMOUS = 'unanimous';

    /**
     * Majority of non-abstaining voters must ALLOW.
     */
    case CONSENSUS = 'consensus';
}
