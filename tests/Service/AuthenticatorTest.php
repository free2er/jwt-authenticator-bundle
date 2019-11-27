<?php

declare(strict_types=1);

namespace Free2er\Jwt\Service;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use UnexpectedValueException;

/**
 * Тест аутентификатора
 */
class AuthenticatorTest extends TestCase
{
    /**
     * Аутентификатор
     *
     * @var Authenticator
     */
    private $authenticator;

    /**
     * HTTP-запрос
     *
     * @var Request
     */
    private $request;

    /**
     * Устанавливает параметры окружения
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->authenticator = new Authenticator();
        $this->request       = new Request();
    }

    /**
     * Очищает параметры окружения
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->authenticator = null;
        $this->request       = null;
    }

    /**
     * Проверяет аутентификацию пользователя
     */
    public function testAuthentication(): void
    {
        $user = $this->createUser();

        $provider = $this->createUserProvider();
        $provider
            ->expects($this->once())
            ->method('loadUserByUsername')
            ->with('test')
            ->willReturn($user);

        $this->assertSame($user, $this->authenticator->getUser('test', $provider));
    }

    /**
     * Проверяет ошибку аутентификации для некорректного ключа доступа
     */
    public function testAuthenticationErrorForInvalidCredentials(): void
    {
        $provider = $this->createUserProvider();
        $provider
            ->expects($this->once())
            ->method('loadUserByUsername')
            ->with('test')
            ->willThrowException(new UsernameNotFoundException());

        $this->expectException(AuthenticationException::class);
        $this->authenticator->getUser('test', $provider);
    }

    /**
     * Проверяет обработку запроса аутентификации
     */
    public function testAuthenticationStart(): void
    {
        $response = $this->authenticator->start($this->request);
        $this->assertUnauthorizedResponse($response);
    }

    /**
     * Проверяет обработку ошибки аутентификации
     */
    public function testAuthenticationFailure(): void
    {
        $response = $this->authenticator->onAuthenticationFailure($this->request, $this->createAuthenticationError());
        $this->assertUnauthorizedResponse($response);
    }

    /**
     * Проверяет обработку успешной аутентификации
     */
    public function testAuthenticationSuccess(): void
    {
        $this->assertNull($this->authenticator->onAuthenticationSuccess($this->request, $this->createToken(), 'test'));
    }

    /**
     * Проверяет отсутствие хранения сведений о пользователе
     */
    public function testNoSupportsForRememberMe(): void
    {
        $this->assertFalse($this->authenticator->supportsRememberMe());
    }

    /**
     * Проверяет поддержку авторизации с Bearer-токеном
     */
    public function testSupportsForBearerAuthorization(): void
    {
        $this->request->headers->set('Authorization', 'Bearer test.jwt.key');
        $this->assertTrue($this->authenticator->supports($this->request));
    }

    /**
     * Проверяет отсутствие поддержки авторизации с Basic-токеном
     */
    public function testNoSupportsForBasicAuthorization(): void
    {
        $this->request->headers->set('Authorization', 'Basic test');
        $this->assertFalse($this->authenticator->supports($this->request));
    }

    /**
     * Проверяет отсутствие поддержки авторизации с запросом без заголовка авторизации
     */
    public function testNoSupportsForEmptyAuthorization(): void
    {
        $this->assertFalse($this->authenticator->supports($this->request));
    }

    /**
     * Проверяет извлечение Bearer-токена
     */
    public function testCredentialsForBearerAuthorization(): void
    {
        $this->request->headers->set('Authorization', 'Bearer test.jwt.key');
        $this->assertSame('test.jwt.key', $this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет ошибку извлечения Basic-токена
     */
    public function testCredentialsErrorForBasicAuthorization(): void
    {
        $this->request->headers->set('Authorization', 'Basic test');

        $this->expectException(UnexpectedValueException::class);
        $this->authenticator->getCredentials($this->request);
    }

    /**
     * Проверяет ошибку извлечения токена из запроса без заголовка авторизации
     */
    public function testCredentialsErrorForEmptyAuthorization(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->authenticator->getCredentials($this->request);
    }

    /**
     * Проверяет валидацию токена
     */
    public function testCredentialsCheck(): void
    {
        $this->assertTrue($this->authenticator->checkCredentials('test', $this->createUser()));
    }

    /**
     * Проверяет ответ на наличие сведений об ошибке авторизации
     *
     * @param Response $response
     */
    private function assertUnauthorizedResponse(Response $response): void
    {
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $this->assertJsonStringEqualsJsonString('{"error": "unauthorized"}', $response->getContent());
    }

    /**
     * Создает ошибку аутентификации
     *
     * @return AuthenticationException|MockObject
     */
    private function createAuthenticationError(): AuthenticationException
    {
        return $this->createMock(AuthenticationException::class);
    }

    /**
     * Создает ключ аутентификации
     *
     * @return TokenInterface|MockObject
     */
    private function createToken(): TokenInterface
    {
        return $this->createMock(TokenInterface::class);
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
     * Создает провайдера пользователей
     *
     * @return UserProviderInterface|MockObject
     */
    private function createUserProvider(): UserProviderInterface
    {
        return $this->createMock(UserProviderInterface::class);
    }
}
