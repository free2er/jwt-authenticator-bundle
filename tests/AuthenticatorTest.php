<?php

declare(strict_types = 1);

namespace Free2er\Jwt;

use Carbon\Carbon;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\Test\TestLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Throwable;

/**
 * Тест аутентификатора
 */
class AuthenticatorTest extends TestCase
{
    /**
     * Идентификатор JWT
     *
     * @var string
     */
    private $id = 'jwt';

    /**
     * Идентификатор клиентского приложения
     *
     * @var string
     */
    private $client = 'client';

    /**
     * Идентификатор пользователя
     *
     * @var string
     */
    private $user = 'user';

    /**
     * Текущее время
     *
     * @var int
     */
    private $now;

    /**
     * Время завершения срока действия JWT
     *
     * @var int
     */
    private $expiration;

    /**
     * Парсер ключа JWT
     *
     * @var Parser
     */
    private $parser;

    /**
     * Шифратор ключа JWT
     *
     * @var Signer
     */
    private $signer;

    /**
     * Открытый ключ сервера OAuth
     *
     * @var Signer\Key
     */
    private $key;

    /**
     * HTTP-запрос
     *
     * @var Request
     */
    private $request;

    /**
     * Логгер
     *
     * @var TestLogger
     */
    private $logger;

    /**
     * Аутентификатор
     *
     * @var Authenticator
     */
    private $authenticator;

    /**
     * Устанавливает окружение теста
     *
     * @throws Throwable
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->now           = Carbon::now()->getTimestamp();
        $this->expiration    = $this->now + 1;
        $this->parser        = new Parser();
        $this->signer        = new Signer\Rsa\Sha512();
        $this->key           = new Signer\Key(sprintf('file://%s/Resources/public.key', __DIR__));
        $this->request       = new Request();
        $this->logger        = new TestLogger();
        $this->authenticator = new Authenticator($this->parser, $this->signer, $this->key);
    }

    /**
     * Очщает окружение теста
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->now           = null;
        $this->expiration    = null;
        $this->parser        = null;
        $this->signer        = null;
        $this->key           = null;
        $this->request       = null;
        $this->logger        = null;
        $this->authenticator = null;
    }

    /**
     * Проверяет аутентификацию без ключа
     */
    public function testAuthenticationWithNoToken(): void
    {
        $this->assertFalse($this->authenticator->supports($this->request));
        $this->assertFalse($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет аутентификацию по Basic ключу в заголовке авторизации
     */
    public function testAuthenticationWithBasicToken(): void
    {
        $this->request->headers->set('authorization', 'Basic dGVzdDp0ZXN0');

        $this->assertFalse($this->authenticator->supports($this->request));
        $this->assertFalse($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет аутентификацию по Bearer ключу в заголовке авторизации
     */
    public function testAuthenticationWithBearerToken(): void
    {
        $this->request->headers->set('authorization', sprintf('Bearer %s', $this->createJwt()));

        $this->assertTrue($this->authenticator->supports($this->request));
        $this->assertJwt($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет аутентификацию по ключу в переопределенном заголовке авторизации
     */
    public function testAuthenticationWithTokenInCustomHeader(): void
    {
        $this->request->headers->set('test', sprintf('Bearer %s', $this->createJwt()));
        $this->authenticator->setHeader('test');

        $this->assertTrue($this->authenticator->supports($this->request));
        $this->assertJwt($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет выключение аутентификации по заголовку авторизации
     */
    public function testDisablingAuthenticationWithTokenInHeader(): void
    {
        $this->request->headers->set('authorization', sprintf('Bearer %s', $this->createJwt()));
        $this->authenticator->setHeader('');

        $this->assertFalse($this->authenticator->supports($this->request));
        $this->assertFalse($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет аутентификацию по ключу в GET-параметре
     */
    public function testAuthenticationWithQueryToken(): void
    {
        $this->request->query->set('token', $this->createJwt());

        $this->assertTrue($this->authenticator->supports($this->request));
        $this->assertJwt($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет аутентификацию по ключу в переопределенном GET-параметре
     */
    public function testAuthenticationWithCustomQueryToken(): void
    {
        $this->request->query->set('test', $this->createJwt());
        $this->authenticator->setParameter('test');

        $this->assertTrue($this->authenticator->supports($this->request));
        $this->assertJwt($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет выключение аутентификации по ключу в GET-параметре
     */
    public function testDisablingAuthenticationWithQueryToken(): void
    {
        $this->request->query->set('token', $this->createJwt());
        $this->authenticator->setParameter('');

        $this->assertFalse($this->authenticator->supports($this->request));
        $this->assertFalse($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет аутентификацию по некорректному ключу
     */
    public function testAuthenticationWithInvalidToken(): void
    {
        $this->request->query->set('token', 'some.invalid.jwt');

        $this->assertTrue($this->authenticator->supports($this->request));
        $this->assertFalse($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет аутентификацию по просроченному ключу
     */
    public function testAuthenticationWithExpiredToken(): void
    {
        $this->expiration = $this->now - 1;
        $this->request->query->set('token', $this->createJwt());

        $this->assertTrue($this->authenticator->supports($this->request));
        $this->assertFalse($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет аутентификацию по ключу неизвестного сервера авторизации
     */
    public function testAuthenticationWithUntrustedToken(): void
    {
        $this->request->query->set('token', $this->createJwt('untrusted'));

        $this->assertTrue($this->authenticator->supports($this->request));
        $this->assertFalse($this->authenticator->getCredentials($this->request));
    }

    /**
     * Проверяет журналирование попыток аутентификации без ключа
     */
    public function testLogEmptyToken(): void
    {
        $this->authenticator->setLogger($this->logger);
        $this->authenticator->getCredentials($this->request);

        $this->assertEquals('alert', $this->logger->records[0]['level'] ?? null);
        $this->assertEquals('JWT not found', $this->logger->records[0]['message'] ?? null);
    }

    /**
     * Проверяет журналирование попыток аутентификации по некорректному ключу
     */
    public function testLogInvalidToken(): void
    {
        $this->request->query->set('token', 'some.invalid.jwt');

        $this->authenticator->setLogger($this->logger);
        $this->authenticator->getCredentials($this->request);

        $this->assertEquals('error', $this->logger->records[0]['level'] ?? null);
        $this->assertEquals('JWT error', $this->logger->records[0]['message'] ?? null);
        $this->assertEquals('some.invalid.jwt', $this->logger->records[0]['context']['jwt'] ?? null);
    }

    /**
     * Проверяет журналирование попыток аутентификации по просроченному ключу
     */
    public function testLogExpiredToken(): void
    {
        $this->expiration = $this->now - 1;

        $token = (string) $this->createJwt();
        $this->request->query->set('token', $token);

        $this->authenticator->setLogger($this->logger);
        $this->authenticator->getCredentials($this->request);

        $this->assertEquals('alert', $this->logger->records[0]['level'] ?? null);
        $this->assertEquals('JWT expired', $this->logger->records[0]['message'] ?? null);
        $this->assertEquals($token, $this->logger->records[0]['context']['jwt'] ?? null);
    }

    /**
     * Проверяет журналирование попыток аутентификации по ключу неизвестного сервера авторизации
     */
    public function testLogUntrustedToken(): void
    {
        $token = (string) $this->createJwt('untrusted');
        $this->request->query->set('token', $token);

        $this->authenticator->setLogger($this->logger);
        $this->authenticator->getCredentials($this->request);

        $this->assertEquals('alert', $this->logger->records[0]['level'] ?? null);
        $this->assertEquals('JWT signature verification failed', $this->logger->records[0]['message'] ?? null);
        $this->assertEquals($token, $this->logger->records[0]['context']['jwt'] ?? null);
    }

    /**
     * Проверяет аутентификацию
     *
     * @throws Throwable
     */
    public function testAuthentication(): void
    {
        $token = $this->createJwt();
        $user  = $this->createUser();

        $provider = $this->createUserProvider();
        $provider
            ->expects($this->once())
            ->method('loadUserByUsername')
            ->with($token)
            ->willReturn($user);

        $this->authenticator->getUser($token, $provider);
    }

    /**
     * Проверяет безуспешную аутентификацию
     *
     * @throws Throwable
     */
    public function testAuthenticationError(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->authenticator->getUser('some.invalid.jwt', $this->createUserProvider());
    }

    /**
     * Проверяет поддержку работы с JWT
     *
     * @throws Throwable
     */
    public function testCredentialsCheck(): void
    {
        $user = $this->createUser();

        $this->assertTrue($this->authenticator->checkCredentials($this->createJwt(), $user));
        $this->assertFalse($this->authenticator->checkCredentials('some.invalid.jwt', $user));
    }

    /**
     * Проверяет ответы с результатом аутентификации
     *
     * @throws Throwable
     */
    public function testAuthenticationResponse(): void
    {
        $exception = new AuthenticationException();

        $this->assertErrorResponse($this->authenticator->start($this->request));
        $this->assertErrorResponse($this->authenticator->start($this->request, $exception));
        $this->assertErrorResponse($this->authenticator->onAuthenticationFailure($this->request, $exception));
        $this->assertNull($this->authenticator->onAuthenticationSuccess($this->request, $this->createToken(), ''));
    }

    /**
     * Проверяет отсутствие поддержки сессий
     */
    public function testStatelessMode(): void
    {
        $this->assertFalse($this->authenticator->supportsRememberMe());
    }

    /**
     * Проверяет состав JWT
     *
     * @param Token $token
     */
    private function assertJwt(Token $token): void
    {
        $this->assertEquals($this->id, $token->getClaim('jti'));
        $this->assertEquals($this->client, $token->getClaim('aud'));
        $this->assertEquals($this->user, $token->getClaim('sub'));
        $this->assertEquals($this->now, $token->getClaim('iat'));
        $this->assertEquals($this->now, $token->getClaim('nbf'));
        $this->assertEquals($this->expiration, $token->getClaim('exp'));
    }

    /**
     * Проверяет ответ об ошибке аутентификации
     *
     * @param Response $response
     */
    private function assertErrorResponse(Response $response): void
    {
        $this->assertEquals(401, $response->getStatusCode());
    }

    /**
     * Создает JWT
     *
     * @param string $key
     *
     * @return Token
     */
    private function createJwt(string $key = 'private'): Token
    {
        $builder = new Builder();
        $builder->setId($this->id, true);
        $builder->setAudience($this->client);
        $builder->setSubject($this->user);
        $builder->setIssuedAt($this->now);
        $builder->setNotBefore($this->now);
        $builder->setExpiration($this->expiration);

        $key = new Signer\Key(sprintf('file://%s/Resources/%s.key', __DIR__, $key));
        $builder->sign($this->signer, $key);

        return $builder->getToken();
    }

    /**
     * Создает ключ аутентификации
     *
     * @return TokenInterface|MockObject
     *
     * @throws Throwable
     */
    private function createToken(): TokenInterface
    {
        return $this->createMock(TokenInterface::class);
    }

    /**
     * Создает пользователя
     *
     * @return UserInterface|MockObject
     *
     * @throws Throwable
     */
    private function createUser(): UserInterface
    {
        return $this->createMock(UserInterface::class);
    }

    /**
     * Создает провайдера пользователей
     *
     * @return UserProviderInterface|MockObject
     *
     * @throws Throwable
     */
    private function createUserProvider(): UserProviderInterface
    {
        return $this->createMock(UserProviderInterface::class);
    }
}
