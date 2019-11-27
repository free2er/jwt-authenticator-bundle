<?php

declare(strict_types=1);

namespace Free2er\Jwt\Entity;

use Lcobucci\JWT\Token;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Пользователь
 */
class User implements UserInterface, EquatableInterface
{
    /**
     * Префикс роли
     *
     * @const string
     */
    private const ROLE_PREFIX = 'ROLE_';

    /**
     * Ключ доступа
     *
     * @var Token
     */
    private $token;

    /**
     * Параметр списка ролей
     *
     * @var string
     */
    private $roles;

    /**
     * Кеш списка ролей
     *
     * @var string[]
     */
    private $cache;

    /**
     * Конструктор
     *
     * @param Token  $token
     * @param string $roles
     */
    public function __construct(Token $token, string $roles)
    {
        $this->token = $token;
        $this->roles = $roles;
    }

    /**
     * Сравнивает пользователей
     *
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isEqualTo(UserInterface $user)
    {
        return $user instanceof self && $user->getUsername() === $this->getUsername();
    }

    /**
     * Возвращает приложение
     *
     * @return string
     */
    public function getApplication(): string
    {
        return (string) $this->getClaim('aud');
    }

    /**
     * Возвращает имя пользователя
     *
     * @return string
     */
    public function getUsername()
    {
        return (string) $this->getClaim('sub');
    }

    /**
     * Возвращает роли
     *
     * @return string[]
     */
    public function getRoles()
    {
        if ($this->cache !== null) {
            return $this->cache;
        }

        $this->cache = [];

        foreach ($this->token->getClaim($this->roles, []) ?: [] as $role) {
            if (!$role = $this->normalizeRole((string) $role)) {
                continue;
            }

            if (!in_array($role, $this->cache, true)) {
                $this->cache[] = $role;
            }
        }

        return $this->cache;
    }

    /**
     * Возвращает значение произвольного параметра
     *
     * @param string $name
     * @param mixed  $default
     *
     * @return mixed
     */
    public function getClaim(string $name, $default = null)
    {
        return $this->token->getClaim($name, $default);
    }

    /**
     * Возвращает пароль
     *
     * @return null
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * Возвращает соль
     *
     * @return null
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * Очищает сведения о пароле
     */
    public function eraseCredentials()
    {
    }

    /**
     * Нормализует роль
     *
     * @param string $role
     *
     * @return string|null
     */
    private function normalizeRole(string $role): ?string
    {
        if (!$role = trim($role)) {
            return null;
        }

        $role = str_replace('.', '_', strtoupper($role));
        $role = strpos($role, static::ROLE_PREFIX) === 0 ? $role : static::ROLE_PREFIX . $role;

        return $role;
    }
}
