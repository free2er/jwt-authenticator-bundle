<?php

declare(strict_types = 1);

namespace Free2er\Jwt;

use Carbon\Carbon;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Throwable;

/**
 * Аутентификатор
 */
class Authenticator extends AbstractGuardAuthenticator implements LoggerAwareInterface
{
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
     * Логгер
     *
     * @var LoggerInterface
     */
    private $logger;

    /**
     * Заголовок запроса
     *
     * @var string
     */
    private $header = 'authorization';

    /**
     * Параметр запроса
     *
     * @var string
     */
    private $parameter = 'token';

    /**
     * Конструктор
     *
     * @param Parser               $parser
     * @param Signer               $signer
     * @param Signer\Key           $key
     * @param LoggerInterface|null $logger
     */
    public function __construct(Parser $parser, Signer $signer, Signer\Key $key, LoggerInterface $logger = null)
    {
        $this->parser = $parser;
        $this->signer = $signer;
        $this->key    = $key;
        $this->logger = $logger ?: new NullLogger();
    }

    /**
     * Устанавливает логгер
     *
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Устанавливает заголовок запроса
     *
     * @param string $header
     */
    public function setHeader(string $header): void
    {
        $this->header = $header;
    }

    /**
     * Устанавливает параметр запроса
     *
     * @param string $parameter
     */
    public function setParameter(string $parameter): void
    {
        $this->parameter = $parameter;
    }

    /**
     * Проверяет возможность хранения информации о пользователе
     *
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }

    /**
     * Проверяет наличие сведений для аутентификации
     *
     * @param Request $request
     *
     * @return bool
     */
    public function supports(Request $request)
    {
        if ($this->header && $request->headers->has($this->header)) {
            return true;
        }

        if ($this->parameter && $request->query->has($this->parameter)) {
            return true;
        }

        return false;
    }

    /**
     * Возвращает сведения для аутентификации
     *
     * @param Request $request
     *
     * @return Token|bool
     */
    public function getCredentials(Request $request)
    {
        if (!$jwt = $this->getToken($request)) {
            $this->logger->alert('JWT not found');
            return false;
        }

        try {
            $token = $this->parser->parse($jwt);

            if (!$token->verify($this->signer, $this->key)) {
                $this->logger->alert('JWT signature verification failed', ['jwt' => $jwt]);
                return false;
            }

            if (!$token->validate($this->createTokenValidator())) {
                $this->logger->alert('JWT expired', ['jwt' => $jwt]);
                return false;
            }
        } catch (Throwable $exception) {
            $this->logger->error('JWT error', [
                'exception' => $exception,
                'jwt'       => $jwt,
            ]);

            return false;
        }

        return $token;
    }

    /**
     * Аутентифицирует пользователя
     *
     * @param mixed                 $credentials
     * @param UserProviderInterface $userProvider
     *
     * @return UserInterface
     *
     * @throws AuthenticationException
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if (!$credentials instanceof Token) {
            throw new AuthenticationException();
        }

        return $userProvider->loadUserByUsername($credentials);
    }

    /**
     * Проверяет пароль пользователя
     *
     * @param mixed         $credentials
     * @param UserInterface $user
     *
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return $credentials instanceof Token;
    }

    /**
     * Обрабатывает событие запроса аутентификации
     *
     * @param Request                 $request
     * @param AuthenticationException $authException
     *
     * @return Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return $this->createUnauthorizedResponse();
    }

    /**
     *  Обрабатывает событие безуспешной аутентификации
     *
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return $this->createUnauthorizedResponse();
    }

    /**
     * Обрабатывает событие успешной аутентификации
     *
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey
     *
     * @return null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return null;
    }

    /**
     * Возвращает ключ доступа
     *
     * @param Request $request
     *
     * @return string
     */
    private function getToken(Request $request): string
    {
        if ($token = $this->fromHeader($request)) {
            return $token;
        }

        if ($token = $this->fromQuery($request)) {
            return $token;
        }

        return '';
    }

    /**
     * Извлекает ключ из заголовоков запроса
     *
     * @param Request $request
     *
     * @return string
     */
    private function fromHeader(Request $request): string
    {
        if (!$this->header) {
            return '';
        }

        if (!$token = $request->headers->get($this->header, '')) {
            return '';
        }

        if (is_array($token)) {
            $token = reset($token);
        }

        return trim(preg_replace('/^(?:\s+)?Bearer\s/', '', (string) $token));
    }

    /**
     * Извлекает ключ из параметров запроса
     *
     * @param Request $request
     *
     * @return string
     */
    private function fromQuery(Request $request): string
    {
        if (!$this->parameter) {
            return '';
        }

        return (string) $request->query->get($this->parameter, '');
    }

    /**
     * Создает валидатор ключа JWT
     *
     * @return ValidationData
     */
    private function createTokenValidator(): ValidationData
    {
        return new ValidationData(Carbon::now()->getTimestamp());
    }

    /**
     * Создает ответ об ошибке авторизации
     *
     * @return Response
     */
    private function createUnauthorizedResponse(): Response
    {
        return new Response('', Response::HTTP_UNAUTHORIZED);
    }
}
