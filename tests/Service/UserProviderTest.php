<?php

declare(strict_types=1);

namespace Free2er\Jwt\Service;

use Carbon\Carbon;
use Free2er\Jwt\Entity\User;
use Free2er\Jwt\Exception\TokenException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Тест провайдера пользователей
 */
class UserProviderTest extends TestCase
{
    /**
     * Провайдер пользователей
     *
     * @var UserProvider
     */
    private $provider;

    /**
     * Шифратор JWT
     *
     * @var Signer
     */
    private $signer;

    /**
     * Открытый ключ сервера авторизации
     *
     * @var Signer\Key
     */
    private $key;

    /**
     * Параметр списка ролей
     *
     * @var string
     */
    private $roles = 'roles';

    /**
     * Текущее время
     *
     * @var int
     */
    private $now = 1574879331;

    /**
     * Устанавливает параметры окружения
     */
    protected function setUp(): void
    {
        parent::setUp();

        $now = Carbon::createFromTimestamp($this->now);
        Carbon::setTestNow($now);

        $this->signer   = new Signer\Rsa\Sha512();
        $this->key      = new Signer\Key('file://' . realpath(dirname(__DIR__) . '/Resources/public.key'));
        $this->provider = new UserProvider($this->signer, $this->key, $this->roles);
    }

    /**
     * Очищает параметры окружения
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        Carbon::setTestNow(null);

        $this->signer   = null;
        $this->key      = null;
        $this->provider = null;
    }

    /**
     * Проверяет данные пользователя
     */
    public function testUser(): void
    {
        $token = $this->createToken();
        $this->assertUser($token, $this->provider->loadUserByUsername((string) $token));
    }

    /**
     * Проверяет создание пользователя
     */
    public function testUserCreation(): void
    {
        $token = $this->createToken();
        $user1 = $this->provider->loadUserByUsername((string) $token);
        $user2 = $this->provider->loadUserByUsername((string) $token);

        $this->assertNotSame($user1, $user2);
        $this->assertTrue($user1->isEqualTo($user2));
    }

    /**
     * Проверяет ошибку создания пользователя для некорректного ключа доступа
     */
    public function testErrorForInvalidToken(): void
    {
        $this->expectException(TokenException::class);
        $this->expectExceptionMessageMatches('/^JWT error/');

        $this->provider->loadUserByUsername('some.invalid.jwt');
    }

    /**
     * Проверяет ошибку создания пользователя для просроченного ключа
     */
    public function testErrorForExpiredToken(): void
    {
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('JWT expired');

        $this->provider->loadUserByUsername((string) $this->createToken(-1));
    }

    /**
     * Проверяет ошибку создания пользователя для ключа с подписью недоверенного сервера
     */
    public function testErrorForUntrustedSignature(): void
    {
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('JWT signature verification failed');

        $this->provider->loadUserByUsername((string) $this->createToken(3600, 'untrusted.key'));
    }

    /**
     * Проверяет обновление данных пользователя
     */
    public function testRefresh(): void
    {
        $user = $this->createUser();
        $this->assertSame($user, $this->provider->refreshUser($user));
    }

    /**
     * Проверяет поддержку класса пользователей
     */
    public function testSupport(): void
    {
        $this->assertTrue($this->provider->supportsClass(User::class));
    }

    /**
     * Проверяет поддержку класса пользователей для некорректного класса
     */
    public function testSupportForInvalidClass(): void
    {
        $this->assertFalse($this->provider->supportsClass(UserInterface::class));
    }

    /**
     * Проверяет данные пользователя
     *
     * @param Token         $token
     * @param UserInterface $user
     */
    private function assertUser(Token $token, UserInterface $user): void
    {
        $roles = [];

        foreach ($token->getClaim($this->roles, []) as $role) {
            $roles[] = 'ROLE_' . strtoupper($role);
        }

        $this->assertSame($token->getClaim('aud'), $user->getApplication());
        $this->assertSame($token->getClaim('sub'), $user->getUsername());
        $this->assertSame($roles, $user->getRoles());
        $this->assertNull($user->getPassword());
        $this->assertNull($user->getSalt());
    }

    /**
     * Создает пользователя
     *
     * @return UserInterface|MockObject
     */
    private function createUser(): UserInterface
    {
        return $this->createMock(UserInterface::class);
    }

    /**
     * Создает ключ доступа
     *
     * @param int    $expiration
     * @param string $key
     *
     * @return Token
     */
    private function createToken(int $expiration = 3600, string $key = 'private.key'): Token
    {
        $builder = new Builder();
        $builder
            ->identifiedBy('token', true)
            ->permittedFor('application')
            ->relatedTo('user')
            ->canOnlyBeUsedAfter($this->now)
            ->issuedAt($this->now)
            ->expiresAt($this->now + $expiration)
            ->withClaim($this->roles, ['test']);

        $key = new Signer\Key('file://' . realpath(dirname(__DIR__) . '/Resources/' . $key));

        return $builder->getToken($this->signer, $key);
    }
}
