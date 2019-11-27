<?php

declare(strict_types=1);

namespace Free2er\Jwt\Entity;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Интерфейс объекта с владельцем
 */
interface OwnedInterface
{
    /**
     * Проверяет является ли пользователь владельцем объекта
     *
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isOwnedBy(UserInterface $user): bool;
}
