<?php

declare(strict_types=1);

namespace Free2er\Jwt\Voter;

use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Абстрактное составное условие
 */
abstract class AbstractAggregateVoter extends Voter
{
    /**
     * Валидатор доступа
     *
     * @var AuthorizationCheckerInterface
     */
    private $checker;

    /**
     * Конструктор
     *
     * @param AuthorizationCheckerInterface $checker
     */
    public function __construct(AuthorizationCheckerInterface $checker)
    {
        $this->checker = $checker;
    }

    /**
     * Проверяет наличие доступа
     *
     * @param string $attribute
     * @param mixed  $subject
     *
     * @return bool
     */
    protected function isGranted(string $attribute, $subject = null): bool
    {
        return $this->checker->isGranted($attribute, $subject);
    }
}
