<?php

declare(strict_types=1);

namespace Free2er\Jwt\ParamConverter;

use Free2er\Jwt\Entity\User;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\ParamConverter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Тест преобразователя пользователей
 */
class UserParamConverterTest extends TestCase
{
    /**
     * Преобразователь пользователей
     *
     * @var UserParamConverter
     */
    private $converter;

    /**
     * HTTP-запрос
     *
     * @var Request
     */
    private $request;

    /**
     * Параметры преобразования
     *
     * @var ParamConverter
     */
    private $configuration;

    /**
     * Хранилище ключей доступа
     *
     * @var TokenStorageInterface|MockObject
     */
    private $storage;

    /**
     * Ключ аутентификации
     *
     * @var TokenInterface|MockObject
     */
    private $token;

    /**
     * Устанавливает параметры окружения
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->storage       = $this->createMock(TokenStorageInterface::class);
        $this->token         = $this->createMock(TokenInterface::class);
        $this->converter     = new UserParamConverter($this->storage);
        $this->request       = new Request();
        $this->configuration = new ParamConverter([]);
    }

    /**
     * Очищает параметры окружения
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->storage       = null;
        $this->token         = null;
        $this->converter     = null;
        $this->request       = null;
        $this->configuration = null;
    }

    /**
     * Проверяет поддержку пользователя
     */
    public function testSupportsUser(): void
    {
        $this->configuration->setClass(User::class);
        $this->assertTrue($this->converter->supports($this->configuration));
    }

    /**
     * Проверяет отсутствие поддержки неподдерживаемого пользователя
     */
    public function testSupportsForUnsupportedUser(): void
    {
        $this->configuration->setClass(UserInterface::class);
        $this->assertFalse($this->converter->supports($this->configuration));
    }

    /**
     * Проверяет преобразование пользователя
     */
    public function testApply(): void
    {
        $user = $this->createMock(User::class);

        $this->storage
            ->expects($this->once())
            ->method('getToken')
            ->willReturn($this->token);

        $this->token
            ->expects($this->once())
            ->method('getUser')
            ->willReturn($user);

        $this->configuration->setName('user');
        $this->assertNull($this->request->attributes->get('user'));

        $this->assertTrue($this->converter->apply($this->request, $this->configuration));
        $this->assertSame($user, $this->request->attributes->get('user'));
    }

    /**
     * Проверяет преобразование неподдерживаемого пользователя
     */
    public function testApplyForUnsupportedUser(): void
    {
        $this->storage
            ->expects($this->once())
            ->method('getToken')
            ->willReturn($this->token);

        $this->token
            ->expects($this->once())
            ->method('getUser')
            ->willReturn($this->createMock(UserInterface::class));

        $this->assertFalse($this->converter->apply($this->request, $this->configuration));
        $this->assertEmpty($this->request->attributes->all());
    }

    /**
     * Проверяет преобразование без пользователя
     */
    public function testApplyForEmptyUser(): void
    {
        $this->storage
            ->expects($this->once())
            ->method('getToken')
            ->willReturn($this->token);

        $this->token
            ->expects($this->once())
            ->method('getUser')
            ->willReturn(null);

        $this->assertFalse($this->converter->apply($this->request, $this->configuration));
        $this->assertEmpty($this->request->attributes->all());
    }

    /**
     * Проверяет преобразование без ключа доступа
     */
    public function testApplyForEmptyToken(): void
    {
        $this->storage
            ->expects($this->once())
            ->method('getToken')
            ->willReturn(null);

        $this->assertFalse($this->converter->apply($this->request, $this->configuration));
        $this->assertEmpty($this->request->attributes->all());
    }
}
