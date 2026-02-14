<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authorization;

use CFXP\Core\Auth\Authorization\Voter\VoterInterface;
use CFXP\Core\Auth\Identity\IdentityInterface;

class Authorizer
{
    /** @var VoterInterface[] */
    /** @var array<string, mixed> */

    private array $voters = [];

    public function __construct(
        private DecisionStrategy $strategy = DecisionStrategy::AFFIRMATIVE,
        private bool $allowIfAllAbstain = false,
    ) {}

    /**
     * Register a voter.
     */
    public function addVoter(VoterInterface $voter): self
    {
        $this->voters[] = $voter;
        return $this;
    }

    /**
     * Change the decision strategy.
     */
    public function setStrategy(DecisionStrategy $strategy): self
    {
        $this->strategy = $strategy;
        return $this;
    }

    /**
     * Check if the identity is authorized to perform the action.
     */
    public function isGranted(IdentityInterface $identity, string $attribute, mixed $subject = null): bool
    {
        return $this->decide($identity, $attribute, $subject) === Decision::ALLOW;
    }

    /**
     * Get the authorization decision.
     */
    public function decide(IdentityInterface $identity, string $attribute, mixed $subject = null): Decision
    {
        $decisions = $this->collectVotes($identity, $attribute, $subject);

        return match ($this->strategy) {
            DecisionStrategy::AFFIRMATIVE => $this->decideAffirmative($decisions),
            DecisionStrategy::UNANIMOUS => $this->decideUnanimous($decisions),
            DecisionStrategy::CONSENSUS => $this->decideConsensus($decisions),
        };
    }

    /**
     * Check if action is allowed (alias for isGranted).
     */
    public function allows(IdentityInterface $identity, string $attribute, mixed $subject = null): bool
    {
        return $this->isGranted($identity, $attribute, $subject);
    }

    /**
     * Check if action is denied.
     */
    public function denies(IdentityInterface $identity, string $attribute, mixed $subject = null): bool
    {
        return !$this->isGranted($identity, $attribute, $subject);
    }

    /**
     * Collect votes from all voters.
     * 
     * @return Decision[]
     */
    /**
     * @return array<string, mixed>
     */
private function collectVotes(IdentityInterface $identity, string $attribute, mixed $subject): array
    {
        $decisions = [];

        foreach ($this->voters as $voter) {
            if (!$voter->supports($attribute, $subject)) {
                continue;
            }

            $decisions[] = $voter->vote($identity, $attribute, $subject);
        }

        return $decisions;
    }

    /**
     * Affirmative: At least one ALLOW, no DENY.
      * @param array<string, bool> $decisions
     */
    private function decideAffirmative(array $decisions): Decision
    {
        $allow = 0;

        foreach ($decisions as $decision) {
            if ($decision === Decision::DENY) {
                return Decision::DENY;
            }

            if ($decision === Decision::ALLOW) {
                $allow++;
            }
        }

        if ($allow > 0) {
            return Decision::ALLOW;
        }

        return $this->allowIfAllAbstain ? Decision::ALLOW : Decision::DENY;
    }

    /**
     * Unanimous: All must ALLOW or ABSTAIN, at least one ALLOW.
      * @param array<string, bool> $decisions
     */
    private function decideUnanimous(array $decisions): Decision
    {
        $allow = 0;

        foreach ($decisions as $decision) {
            if ($decision === Decision::DENY) {
                return Decision::DENY;
            }

            if ($decision === Decision::ALLOW) {
                $allow++;
            }
        }

        if ($allow > 0) {
            return Decision::ALLOW;
        }

        return $this->allowIfAllAbstain ? Decision::ALLOW : Decision::DENY;
    }

    /**
     * Consensus: Majority of non-abstaining voters must ALLOW.
      * @param array<string, bool> $decisions
     */
    private function decideConsensus(array $decisions): Decision
    {
        $allow = 0;
        $deny = 0;

        foreach ($decisions as $decision) {
            if ($decision === Decision::ALLOW) {
                $allow++;
            } elseif ($decision === Decision::DENY) {
                $deny++;
            }
        }

        if ($allow === 0 && $deny === 0) {
            return $this->allowIfAllAbstain ? Decision::ALLOW : Decision::DENY;
        }

        return $allow > $deny ? Decision::ALLOW : Decision::DENY;
    }
}
