<?php

declare(strict_types=1);

namespace Free2er\Jwt\Voter;

use Free2er\Jwt\Entity\OwnedInterface;
use Free2er\Jwt\Entity\User;
use Free2er\Jwt\Exception\UnexpectedTypeException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Условие доступа владельца
 */
class OwnerVoter extends Voter
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
        return $attribute === 'OWNER';
    }

    /**
     * Проверяет права доступа
     *
     * @param string         $attribute
     * @param mixed          $subject
     * @param TokenInterface $token
     *
     * @return bool
     *
     * @throws UnexpectedTypeException
     */
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        if (!$subject instanceof OwnedInterface) {
            throw new UnexpectedTypeException($subject, OwnedInterface::class);
        }

        $user = $token->getUser();

        return $user instanceof User && $subject->isOwnedBy($user);
    }
}
