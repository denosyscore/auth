<?php

declare(strict_types=1);

use Denosys\Auth\Authentication\RecordUserProvider;
use Denosys\Auth\Identity\AuthenticatableInterface;
use Denosys\Database\Connection\ConnectionManager;
use Denosys\Database\Record\Attributes\Table;
use Denosys\Database\Record\Persists;
use Denosys\Database\Record\Record;
use Denosys\Database\Record\Records;
use Denosys\Database\Record\RecordStore;
use PHPUnit\Framework\TestCase;

#[Table('users')]
final class RecordProviderUser implements Record, AuthenticatableInterface
{
    use Persists;

    public ?int $id = null;
    public string $email;
    public string $password;
    public ?string $rememberToken = null;

    public function getAuthIdentifier(): string|int
    {
        return $this->id ?? 0;
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthPassword(): string
    {
        return $this->password;
    }

    public function getRememberToken(): ?string
    {
        return $this->rememberToken;
    }

    public function setRememberToken(string $token): void
    {
        $this->rememberToken = $token;
    }

    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    public function getAuthClaims(): array
    {
        return ['id' => $this->getAuthIdentifier(), 'email' => $this->email];
    }
}

final class RecordUserProviderTest extends TestCase
{
    private RecordUserProvider $provider;

    protected function setUp(): void
    {
        $manager = new ConnectionManager();
        $manager->addConnection('default', ['driver' => 'sqlite', 'database' => ':memory:']);
        $manager->setDefaultConnection('default');
        $manager->connection()->statement('CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL, password TEXT NOT NULL, remember_token TEXT NULL)');
        $manager->connection()->table('users')->insert(['email' => 'a@example.test', 'password' => password_hash('secret', PASSWORD_BCRYPT, ['cost' => 4])]);
        Records::use(new RecordStore($manager));
        $this->provider = new RecordUserProvider(RecordProviderUser::class);
    }

    protected function tearDown(): void
    {
        Records::reset();
    }

    public function testFindsUsersByIdAndCredential(): void
    {
        self::assertSame('a@example.test', $this->user($this->provider->findById(1))->email);
        self::assertSame(1, $this->user($this->provider->findByCredential('email', 'a@example.test'))->id);
        self::assertNull($this->provider->findByCredential('email', 'b@example.test'));
        self::assertNull($this->provider->findById(2));
        self::assertSame('email', $this->provider->getIdentifierField());
    }

    public function testRememberTokensAreSavedAndChecked(): void
    {
        $user = $this->user($this->provider->findById(1));

        $this->provider->updateRememberToken($user, 'token-1');

        self::assertSame('token-1', RecordProviderUser::findOrFail(1)->rememberToken);
        self::assertNotNull($this->provider->findByRememberToken(1, 'token-1'));
        self::assertNull($this->provider->findByRememberToken(1, 'other'));
    }

    public function testAnOutdatedHashIsReplaced(): void
    {
        $user = $this->user($this->provider->findById(1));
        self::assertTrue($this->provider->validatePassword($user, 'secret'));

        $this->provider->rehashPasswordIfRequired($user, 'secret');

        $stored = RecordProviderUser::findOrFail(1)->password;
        self::assertFalse(password_needs_rehash($stored, PASSWORD_DEFAULT));
        self::assertSame($stored, $user->password);
        self::assertTrue(password_verify('secret', $stored));
    }

    public function testARehashDoesNotUndoAConcurrentPasswordChange(): void
    {
        $user = $this->user($this->provider->findById(1));
        $changed = password_hash('changed', PASSWORD_DEFAULT);
        RecordProviderUser::query()->where('id', '=', 1)->update(['password' => $changed]);

        $this->provider->rehashPasswordIfRequired($user, 'secret');

        self::assertSame($changed, RecordProviderUser::findOrFail(1)->password);
    }

    private function user(?AuthenticatableInterface $user): RecordProviderUser
    {
        self::assertInstanceOf(RecordProviderUser::class, $user);

        return $user;
    }
}
