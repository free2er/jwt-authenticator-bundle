<?php

declare(strict_types=1);

namespace Free2er\Jwt\Exception;

use InvalidArgumentException;

/**
 * Ошибка недопустимого типа
 */
class UnexpectedTypeException extends InvalidArgumentException
{
    /**
     * Конструктор
     *
     * @param mixed  $value
     * @param string $expectedType
     */
    public function __construct($value, string $expectedType)
    {
        $type    = is_object($value) ? get_class($value) : gettype($value);
        $message = sprintf('Expected argument of type "%s", "%s" given', $expectedType, $type);

        parent::__construct($message);
    }
}
