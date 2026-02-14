<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authorization\Voter;

use CFXP\Core\Auth\Authorization\Decision;
use CFXP\Core\Auth\Identity\IdentityInterface;

interface VoterInterface
{
    /**
     * Check if this voter supports the given attribute and subject.
     * 
     * @param string $attribute The action/permission being checked (e.g., 'edit', 'delete')
     * @param mixed $subject The resource being accessed (can be null for global permissions)
     */
    public function supports(string $attribute, mixed $subject): bool;

    /**
     * Vote on whether the identity can perform the action on the subject.
     * 
     * @param IdentityInterface $identity The identity requesting access
     * @param string $attribute The action/permission being checked
     * @param mixed $subject The resource being accessed
     * @return Decision ALLOW, DENY, or ABSTAIN
     */
    public function vote(IdentityInterface $identity, string $attribute, mixed $subject): Decision;
}
