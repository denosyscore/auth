<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authorization\Voter;

use CFXP\Core\Auth\Authorization\Decision;
use CFXP\Core\Auth\Identity\IdentityInterface;

class RoleVoter implements VoterInterface
{
    private const ROLE_PREFIX = 'ROLE_';

    public function supports(string $attribute, mixed $subject): bool
    {
        return str_starts_with($attribute, self::ROLE_PREFIX);
    }

    public function vote(IdentityInterface $identity, string $attribute, mixed $subject): Decision
    {
        if (!$this->supports($attribute, $subject)) {
            return Decision::ABSTAIN;
        }

        $role = strtolower(substr($attribute, strlen(self::ROLE_PREFIX)));

        if ($identity->hasRole($role)) {
            return Decision::ALLOW;
        }

        if ($identity->hasRole($attribute)) {
            return Decision::ALLOW;
        }

        return Decision::DENY;
    }
}
