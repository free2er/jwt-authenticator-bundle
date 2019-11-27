<?php

declare(strict_types=1);

namespace Free2er\Jwt\Exception;

use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Throwable;

/**
 * Ошибка проверки ключа доступа
 */
class TokenException extends UsernameNotFoundException
{
    /**
     * Создает ошибку проверки подписи
     *
     * @return static
     */
    public static function invalidSignature(): self
    {
        return new self('JWT signature verification failed');
    }

    /**
     * Создает ошибку проверки срока действия
     *
     * @return static
     */
    public static function expiredToken(): self
    {
        return new self('JWT expired');
    }

    /**
     * Оборачивает исключение
     *
     * @param string    $jwt
     * @param Throwable $exception
     *
     * @return static
     */
    public static function wrap(string $jwt, Throwable $exception): self
    {
        if (!$exception instanceof self) {
            $exception = new self('JWT error: ' . $exception->getMessage(), $exception->getCode(), $exception);
        }

        $exception->setUsername($jwt);

        return $exception;
    }
}
