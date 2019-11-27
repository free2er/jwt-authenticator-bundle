<?php

declare(strict_types=1);

namespace Free2er\Jwt\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Условие доступа администратора
 */
class AdminVoter extends Voter
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
        return $attribute === 'ADMIN';
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
        return in_array('ROLE_ADMIN', $token->getRoleNames(), true);
    }
}
