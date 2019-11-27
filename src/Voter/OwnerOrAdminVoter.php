<?php

declare(strict_types=1);

namespace Free2er\Jwt\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Условие доступа владельца или администратора
 */
class OwnerOrAdminVoter extends AbstractAggregateVoter
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
        return $attribute === 'OWNER_OR_ADMIN';
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
        return $this->isGranted('OWNER', $subject) || $this->isGranted('ADMIN', $subject);
    }
}
