<?php

declare(strict_types = 1);

namespace Free2er\Jwt\User;

use Lcobucci\JWT\Token;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Пользователь
 */
class User implements UserInterface, EquatableInterface
{
    /**
     * Ключ JWT
     *
     * @var Token
     */
    private $token;

    /**
     * Ключ прав доступа
     *
     * @var string
     */
    private $scopeKey;

    /**
     * Конструктор
     *
     * @param Token  $token
     * @param string $scopeKey
     */
    public function __construct(Token $token, string $scopeKey)
    {
        $this->token    = $token;
        $this->scopeKey = $scopeKey;
    }

    /**
     * Возвращает клиентское приложение
     *
     * @return string
     */
    public function getClient(): string
    {
        return (string) $this->getClaim('aud');
    }

    /**
     * Возвращает пользователя
     *
     * @return string
     */
    public function getSubject(): string
    {
        return (string) $this->getClaim('sub');
    }

    /**
     * Возвращает параметр ключа доступа
     *
     * @param string $claim
     *
     * @return mixed
     */
    public function getClaim(string $claim)
    {
        return $this->token->hasClaim($claim) ? $this->token->getClaim($claim) : null;
    }

    /**
     * Возвращает права доступа
     *
     * @return string[]
     */
    public function getRoles()
    {
        return $this->getClaim($this->scopeKey) ?: [];
    }

    /**
     * Возвращает пароль
     *
     * @return string
     */
    public function getPassword()
    {
        return '';
    }

    /**
     * Возвращает соль
     *
     * @return string
     */
    public function getSalt()
    {
        return '';
    }

    /**
     * Возвращает имя пользователя
     *
     * @return string
     */
    public function getUsername()
    {
        return $this->getSubject();
    }

    /**
     * Очищает секретную информацию перед сериализацией
     */
    public function eraseCredentials()
    {
    }

    /**
     * Проверяет равенство пользователей
     *
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isEqualTo(UserInterface $user)
    {
        if (!$user instanceof static) {
            return false;
        }

        if ($user->getUsername() !== $this->getUsername()) {
            return false;
        }

        return true;
    }
}
