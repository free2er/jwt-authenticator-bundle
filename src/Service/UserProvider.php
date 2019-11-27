<?php

declare(strict_types=1);

namespace Free2er\Jwt\Service;

use Carbon\Carbon;
use Free2er\Jwt\Entity\User;
use Free2er\Jwt\Exception\TokenException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Throwable;

/**
 * Провайдер пользователей
 */
class UserProvider implements UserProviderInterface
{
    /**
     * Шифратор JWT
     *
     * @var Signer
     */
    private $signer;

    /**
     * Открытый ключ сервера авторизации
     *
     * @var Signer\Key
     */
    private $key;

    /**
     * Параметр списка ролей
     *
     * @var string
     */
    private $roles;

    /**
     * Конструктор
     *
     * @param Signer     $signer
     * @param Signer\Key $key
     * @param string     $roles
     */
    public function __construct(Signer $signer, Signer\Key $key, string $roles)
    {
        $this->signer = $signer;
        $this->key    = $key;
        $this->roles  = $roles;
    }

    /**
     * Возвращает пользователя
     *
     * @param string $username
     *
     * @return User
     *
     * @throws TokenException
     */
    public function loadUserByUsername(string $username)
    {
        return new User($this->createToken($username), $this->roles);
    }

    /**
     * Обновляет данные пользователя
     *
     * @param UserInterface $user
     *
     * @return UserInterface
     */
    public function refreshUser(UserInterface $user)
    {
        return $user;
    }

    /**
     * Проверяет поддержку класса пользователей
     *
     * @param string $class
     *
     * @return bool
     */
    public function supportsClass(string $class)
    {
        return $class === User::class;
    }

    /**
     * Создает ключ доступа
     *
     * @param string $jwt
     *
     * @return Token
     *
     * @throws TokenException
     */
    private function createToken(string $jwt): Token
    {
        $parser    = new Parser();
        $validator = new ValidationData(Carbon::now()->getTimestamp());

        try {
            $token = $parser->parse($jwt);

            if (!$token->verify($this->signer, $this->key)) {
                throw TokenException::invalidSignature();
            }

            if (!$token->validate($validator)) {
                throw TokenException::expiredToken();
            }
        } catch (Throwable $exception) {
            throw TokenException::wrap($jwt, $exception);
        }

        return $token;
    }
}
