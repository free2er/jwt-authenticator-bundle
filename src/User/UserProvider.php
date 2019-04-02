<?php

declare(strict_types = 1);

namespace Free2er\Jwt\User;

use Lcobucci\JWT\Token;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Провайдер пользователей
 */
class UserProvider implements UserProviderInterface
{
    /**
     * Ключ прав доступа
     *
     * @var string
     */
    private $scopeKey;

    /**
     * Конструктор
     *
     * @param string $scopeKey
     */
    public function __construct(string $scopeKey)
    {
        $this->scopeKey = $scopeKey;
    }

    /**
     * Возвращает пользователя
     *
     * @param Token|string $token
     *
     * @return UserInterface
     *
     * @throws UsernameNotFoundException
     */
    public function loadUserByUsername($token)
    {
        if (!$token instanceof Token) {
            throw new UsernameNotFoundException();
        }

        return new User($token, $this->scopeKey);
    }

    /**
     * Актуализирует сведения о пользователе
     *
     * @param UserInterface $user
     *
     * @return UserInterface
     *
     * @throws UnsupportedUserException
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException();
        }

        return $user;
    }

    /**
     * Проверяет поддержку работы с пользователями заданного класса
     *
     * @param string $class
     *
     * @return bool
     */
    public function supportsClass($class)
    {
        return $class === User::class;
    }
}
