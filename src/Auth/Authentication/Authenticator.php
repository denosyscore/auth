<?php

declare(strict_types=1);

namespace Denosys\Auth\Authentication;

use Denosys\Auth\Authentication\Credential\CredentialInterface;
use Denosys\Auth\Authentication\Credential\PasswordCredential;
use Denosys\Auth\Authentication\Strategy\StrategyInterface;
use Denosys\Auth\Identity\IdentityInterface;
use Denosys\Auth\Identity\AnonymousIdentity;
use Denosys\Auth\Identity\AuthenticatableInterface;
use Denosys\Auth\Events\UserAuthenticated;
use Denosys\Auth\Events\LoginFailed;
use Denosys\Auth\Events\Logout;
use Denosys\Session\SessionInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

class Authenticator
{
    /** @var array<string, StrategyInterface> */
private array $strategies = [];

    private ?IdentityInterface $identity = null;
    private ?AuthenticatableInterface $user = null;
    private bool $resolved = false;

    private const SESSION_KEY = '_auth_user_id';
    private const SESSION_HASH_KEY = '_auth_user_hash';

    public function __construct(
        private readonly SessionInterface $session,
        private readonly UserProviderInterface $userProvider,
        private readonly ?EventDispatcherInterface $dispatcher = null,
    ) {}

    /**
     * Register an authentication strategy.
     */
    public function addStrategy(StrategyInterface $strategy): self
    {
        $this->strategies[$strategy->getName()] = $strategy;
        return $this;
    }

    /**
     * Get a registered strategy by name.
     */
    public function getStrategy(string $name): ?StrategyInterface
    {
        return $this->strategies[$name] ?? null;
    }

    /**
     * Attempt authentication with the appropriate strategy.
     * 
     * If $strategyName is null, we'll find a strategy that supports the credential.
     */
    public function attempt(CredentialInterface $credential, ?string $strategyName = null): Result
    {
        $strategy = $this->resolveStrategy($credential, $strategyName);

        if ($strategy === null) {
            return Result::failure('No suitable authentication strategy found');
        }

        $result = $strategy->authenticate($credential);

        if ($result->isSuccess()) {
            $this->login($result->getIdentity(), $result->getUser());

            // Handle remember-me if requested
            $remember = $result->getMetadataValue('remember', false);
            if ($remember) {
                $this->createRememberToken($result->getUser());
            }

            // Dispatch success event
            $this->dispatchEvent(new UserAuthenticated(
                $result->getUser(),
                $result->getIdentity(),
                $remember
            ));
        } else {
            // Dispatch failure event
            $identifier = $this->extractIdentifier($credential);
            $this->dispatchEvent(new LoginFailed($identifier, $result->getError() ?? 'Invalid credentials'));
        }

        return $result;
    }

    /**
     * Log in a user directly (without credentials).
     */
    public function login(IdentityInterface $identity, AuthenticatableInterface $user): void
    {
        $this->identity = $identity;
        $this->user = $user;
        $this->resolved = true;

        $this->session->put(self::SESSION_KEY, $user->getAuthIdentifier());
        $this->session->put(self::SESSION_HASH_KEY, $this->hashPassword($user));

        $this->session->regenerate();

        $userId = $user->getAuthIdentifier();
        $this->session->setUserId(is_numeric($userId) ? (int) $userId : null);
    }

    /**
     * Log in a user by their ID.
     */
    public function loginById(string|int $id): bool
    {
        $user = $this->userProvider->findById($id);

        if ($user === null) {
            return false;
        }

        $identity = \Denosys\Auth\Identity\Identity::fromAuthenticatable($user);
        $this->login($identity, $user);

        return true;
    }

    /**
     * Log out the current user.
     */
    public function logout(): void
    {
        // Dispatch logout event before clearing user
        if ($this->user !== null) {
            $this->dispatchEvent(new Logout($this->user));
            $this->userProvider->updateRememberToken($this->user, '');
        }

        // Clear the user_id column in the sessions table
        $this->session->setUserId(null);

        $this->identity = null;
        $this->user = null;
        $this->resolved = true;

        $this->session->forget(self::SESSION_KEY);
        $this->session->forget(self::SESSION_HASH_KEY);
        $this->session->regenerate();
    }

    /**
     * Get the current identity (authenticated or anonymous).
     */
    public function identity(): IdentityInterface
    {
        $this->resolveFromSession();

        return $this->identity ?? new AnonymousIdentity();
    }

    /**
     * Get the current authenticated user model.
     */
    public function user(): ?AuthenticatableInterface
    {
        $this->resolveFromSession();

        return $this->user;
    }

    /**
     * Check if the current user is authenticated.
     */
    public function check(): bool
    {
        return $this->identity()->isAuthenticated();
    }

    /**
     * Check if the current user is a guest (not authenticated).
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * Get the authenticated user's ID.
     */
    public function id(): string|int|null
    {
        return $this->check() ? $this->identity()->getId() : null;
    }

    /**
     * Validate credentials without logging in.
     */
    public function validate(CredentialInterface $credential, ?string $strategyName = null): bool
    {
        $strategy = $this->resolveStrategy($credential, $strategyName);

        if ($strategy === null) {
            return false;
        }

        return $strategy->authenticate($credential)->isSuccess();
    }

    /**
     * Resolve the current user from session.
     */
    private function resolveFromSession(): void
    {
        if ($this->resolved) {
            return;
        }

        $this->resolved = true;

        $id = $this->session->get(self::SESSION_KEY);

        if ($id === null) {
            return;
        }

        $user = $this->userProvider->findById($id);

        if ($user === null) {
            $this->logout();
            return;
        }

        // Verify password hash hasn't changed (user didn't change password elsewhere)
        $storedHash = $this->session->get(self::SESSION_HASH_KEY);
        if ($storedHash !== $this->hashPassword($user)) {
            $this->logout();
            return;
        }

        $this->user = $user;
        $this->identity = \Denosys\Auth\Identity\Identity::fromAuthenticatable($user);
    }

    /**
     * Find a strategy that supports the given credential.
     */
    private function resolveStrategy(CredentialInterface $credential, ?string $name): ?StrategyInterface
    {
        if ($name !== null) {
            return $this->strategies[$name] ?? null;
        }

        foreach ($this->strategies as $strategy) {
            if ($strategy->supports($credential)) {
                return $strategy;
            }
        }

        return null;
    }

    /**
     * Create a hash of the user's password for session verification.
     */
    private function hashPassword(AuthenticatableInterface $user): string
    {
        return sha1($user->getAuthPassword());
    }

    /**
     * Create a remember-me token for the user.
     */
    private function createRememberToken(AuthenticatableInterface $user): void
    {
        $token = bin2hex(random_bytes(32));
        $this->userProvider->updateRememberToken($user, $token);

        // The actual cookie creation should be handled by middleware
        // We store the token info in session metadata for the middleware to use
        $this->session->put('_auth_remember_token', $token);
        $this->session->put('_auth_remember_id', $user->getAuthIdentifier());
    }

    /**
     * Dispatch an event if a dispatcher is available.
     */
    private function dispatchEvent(object $event): void
    {
        $this->dispatcher?->dispatch($event);
    }

    /**
     * Extract identifier from credential for event logging.
     */
    private function extractIdentifier(CredentialInterface $credential): string
    {
        if ($credential instanceof PasswordCredential) {
            return $credential->identifier;
        }

        return 'unknown';
    }
}
