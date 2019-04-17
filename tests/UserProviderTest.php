<?php

declare(strict_types = 1);

namespace Free2er\Jwt;

use Free2er\Jwt\User\User;
use Free2er\Jwt\User\UserProvider;
use Lcobucci\JWT\Claim\Basic;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Throwable;

/**
 * Тест провайдера пользователей
 */
class UserProviderTest extends TestCase
{
    /**
     * Ключ прав доступа
     *
     * @var string
     */
    private $scopeKey = 'scopes';

    /**
     * Провайдер пользователей
     *
     * @var UserProvider
     */
    private $provider;

    /**
     * Устанавливает окружение теста
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = new UserProvider($this->scopeKey);
    }

    /**
     * Очщает окружение теста
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->provider = null;
    }

    /**
     * Проверяет переопределение ключа прав доступа
     */
    public function testCustomScopesKey(): void
    {
        $provider = new UserProvider('roles');
        $user     = $provider->loadUserByUsername($this->createJwt(['roles' => ['role1']]));

        $this->assertContains('role1', $user->getRoles());
        $this->assertNotContains('role2', $user->getRoles());
    }

    /**
     * Проверяет пользователя
     *
     * @throws Throwable
     */
    public function testUser(): void
    {
        $user = $this->provider->loadUserByUsername($this->createJwt([
            'aud'    => 'client',
            'sub'    => 'user',
            'key1'   => 'value1',
            'key2'   => 'value2',
            'scopes' => [
                'scope1',
                'scope2',
            ],
        ]));

        $this->assertEquals('client', $user->getClient());
        $this->assertEquals('user', $user->getSubject());
        $this->assertEquals('value1', $user->getClaim('key1'));
        $this->assertEquals('value2', $user->getClaim('key2'));
        $this->assertNull($user->getClaim('key3'));

        $this->assertEquals('user', $user->getUsername());
        $this->assertContains('scope1', $user->getRoles());
        $this->assertContains('scope2', $user->getRoles());
        $this->assertNotContains('scope3', $user->getRoles());
        $this->assertEmpty($user->getPassword());
        $this->assertEmpty($user->getSalt());

        $this->assertTrue($user->isEqualTo(new User($this->createJwt(['sub' => 'user']), $this->scopeKey)));
        $this->assertFalse($user->isEqualTo(new User($this->createJwt(['sub' => 'other']), $this->scopeKey)));
        $this->assertFalse($user->isEqualTo($this->createInvalidUser()));
    }

    /**
     * Проверяет ошибку возврата пользователя
     *
     * @throws Throwable
     */
    public function testUserError(): void
    {
        $this->expectException(UsernameNotFoundException::class);
        $this->provider->loadUserByUsername('some.invalid.jwt');
    }

    /**
     * Проверяет актуализацию сведений о пользователе
     *
     * @throws Throwable
     */
    public function testRefresh(): void
    {
        $user = $this->createUser();
        $this->assertSame($user, $this->provider->refreshUser($user));
    }

    /**
     * Проверяет ошибку актуализации сведений о пользователе
     *
     * @throws Throwable
     */
    public function testRefreshError(): void
    {
        $this->expectException(UnsupportedUserException::class);
        $this->provider->refreshUser($this->createInvalidUser());
    }

    /**
     * Проверяет поддержку классов пользователя
     */
    public function testUserClassSupports(): void
    {
        $this->assertTrue($this->provider->supportsClass(User::class));
        $this->assertFalse($this->provider->supportsClass(UserInterface::class));
    }

    /**
     * Создает JWT
     *
     * @param array $claims
     *
     * @return Token
     */
    private function createJwt(array $claims): Token
    {
        $keys = array_keys($claims);

        return new Token([], array_combine(
            $keys,
            array_map(
                function ($name, $value) {
                    return new Basic($name, $value);
                },
                $keys,
                $claims
            )
        ));
    }

    /**
     * Создает пользователя
     *
     * @return User|MockObject
     *
     * @throws Throwable
     */
    private function createUser(): User
    {
        return $this->createMock(User::class);
    }

    /**
     * Создает некорректного пользователя
     *
     * @return UserInterface|MockObject
     *
     * @throws Throwable
     */
    private function createInvalidUser(): UserInterface
    {
        return $this->createMock(UserInterface::class);
    }
}
