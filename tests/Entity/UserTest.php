<?php

declare(strict_types=1);

namespace Free2er\Jwt\Entity;

use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Тест пользователя
 */
class UserTest extends TestCase
{
    /**
     * Ключ доступа
     *
     * @var Token|MockObject
     */
    private $token;

    /**
     * Пользователь
     *
     * @var User
     */
    private $user;

    /**
     * Параметр списка ролей
     *
     * @var string
     */
    private $roles = 'roles';

    /**
     * Устанавливает параметры окружения
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->token = $this->createMock(Token::class);
        $this->user  = new User($this->token, $this->roles);
    }

    /**
     * Очищает параметры окружения
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->token = null;
        $this->user  = null;
    }

    /**
     * Проверяет сравнение пользователей
     */
    public function testEquals(): void
    {
        $user = $this->createUser(User::class);
        $user
            ->expects($this->any())
            ->method('getUsername')
            ->willReturn('test');

        $this->token
            ->expects($this->any())
            ->method('getClaim')
            ->with('sub')
            ->willReturn('test');

        $this->assertTrue($this->user->isEqualTo($user));
    }

    /**
     * Проверяет сравнение пользователей для неподдерживаемого класса пользователей
     */
    public function testEqualsForUnsupportedUser(): void
    {
        $user = $this->createUser(UserInterface::class);
        $user
            ->expects($this->any())
            ->method('getUsername')
            ->willReturn('test');

        $this->token
            ->expects($this->any())
            ->method('getClaim')
            ->with('sub')
            ->willReturn('test');

        $this->assertFalse($this->user->isEqualTo($user));
    }

    /**
     * Проверяет приложение
     */
    public function testApplication(): void
    {
        $this->token
            ->expects($this->once())
            ->method('getClaim')
            ->with('aud')
            ->willReturn('test');

        $this->assertEquals('test', $this->user->getApplication());
    }

    /**
     * Проверяет имя пользователя
     */
    public function testUsername(): void
    {
        $this->token
            ->expects($this->once())
            ->method('getClaim')
            ->with('sub')
            ->willReturn('test');

        $this->assertEquals('test', $this->user->getUsername());
    }

    /**
     * Проверяет роли
     */
    public function testRoles(): void
    {
        $this->token
            ->expects($this->once())
            ->method('getClaim')
            ->with($this->roles)
            ->willReturn([
                'test',
                'another.test',
                'test',
            ]);

        $this->assertCount(2, $this->user->getRoles());
        $this->assertEquals('ROLE_TEST', $this->user->getRoles()[0]);
        $this->assertEquals('ROLE_ANOTHER_TEST', $this->user->getRoles()[1]);
    }

    /**
     * Проверяет значение произвольного параметра
     */
    public function testClaim(): void
    {
        $this->token
            ->expects($this->once())
            ->method('getClaim')
            ->with('name', 'default')
            ->willReturn(123);

        $this->assertSame(123, $this->user->getClaim('name', 'default'));
    }

    /**
     * Проверяет отсутствие пароля
     */
    public function testPassword(): void
    {
        $this->assertNull($this->user->getPassword());
        $this->assertNull($this->user->getSalt());

        $this->user->eraseCredentials();
        $this->assertNull($this->user->getPassword());
        $this->assertNull($this->user->getSalt());
    }

    /**
     * Создает пользователя
     *
     * @param string $class
     *
     * @return UserInterface|MockObject
     */
    private function createUser(string $class): UserInterface
    {
        return $this->createMock($class);
    }
}
