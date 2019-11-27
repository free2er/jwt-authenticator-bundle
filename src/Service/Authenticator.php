<?php

declare(strict_types=1);

namespace Free2er\Jwt\Service;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use UnexpectedValueException;

/**
 * Аутентификатор
 */
class Authenticator extends AbstractGuardAuthenticator
{
    /**
     * Проверяет возможность аутентификации
     *
     * @param Request $request
     *
     * @return bool
     */
    public function supports(Request $request)
    {
        try {
            $this->getCredentials($request);
        } catch (UnexpectedValueException $exception) {
            return false;
        }

        return true;
    }

    /**
     * Возвращает ключ доступа
     *
     * @param Request $request
     *
     * @return string
     *
     * @throws UnexpectedValueException
     */
    public function getCredentials(Request $request)
    {
        if (!$header = trim((string) $request->headers->get('authorization'))) {
            throw new UnexpectedValueException('Authorization header missed');
        }

        if (!preg_match('/^bearer\s+(?P<jwt>.+)$/i', $header, $match)) {
            throw new UnexpectedValueException('Authorization header contains invalid value');
        }

        return (string) $match['jwt'];
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
        return $userProvider->loadUserByUsername((string) $credentials);
    }

    /**
     * Проверяет пароль
     *
     * @param mixed         $credentials
     * @param UserInterface $user
     *
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    /**
     * Проверяет возможность хранения сведений о пользователе
     *
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }

    /**
     * Обрабатывает запрос аутентификации
     *
     * @param Request                      $request
     * @param AuthenticationException|null $exception
     *
     * @return Response
     */
    public function start(Request $request, AuthenticationException $exception = null)
    {
        return $this->unauthorized();
    }

    /**
     * Обрабатывает ошибку аутентификации
     *
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return Response
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return $this->unauthorized();
    }

    /**
     * Обрабатывает успешную аутентификацию
     *
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey
     *
     * @return null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        return null;
    }

    /**
     * Создает ответ об ошибке авторизации
     *
     * @return Response
     */
    private function unauthorized(): Response
    {
        return new JsonResponse(['error' => 'unauthorized'], Response::HTTP_UNAUTHORIZED);
    }
}
