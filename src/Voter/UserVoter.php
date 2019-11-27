<?php

declare(strict_types=1);

namespace Free2er\Jwt\Voter;

use Free2er\Jwt\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Условие доступа пользователя
 */
class UserVoter extends Voter
{
    /**
     * Проверяет поддержку условия
     *
     * @param string $attribute
     * @param mixed  $subject
     *
     * @return bool
     */
    protected function supports($attribute, $subject)
    {
        return $attribute === 'USER';
    }

    /**
     * Проверяет права доступа
     *
     * @param string         $attribute
     * @param mixed          $subject
     * @param TokenInterface $token
     *
     * @return bool
     */
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();

        return $user instanceof User && $user->getUsername();
    }
}
