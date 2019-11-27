<?php

declare(strict_types=1);

namespace Free2er\Jwt\ParamConverter;

use Free2er\Jwt\Entity\User;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\ParamConverter;
use Sensio\Bundle\FrameworkExtraBundle\Request\ParamConverter\ParamConverterInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Преобразователь пользователей
 */
class UserParamConverter implements ParamConverterInterface
{
    /**
     * Хранилище ключей доступа
     *
     * @var TokenStorageInterface
     */
    private $storage;

    /**
     * Конструктор
     *
     * @param TokenStorageInterface $storage
     */
    public function __construct(TokenStorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Проверяет возможность преобразования параметра
     *
     * @param ParamConverter $configuration
     *
     * @return bool
     */
    public function supports(ParamConverter $configuration)
    {
        return $configuration->getClass() === User::class;
    }

    /**
     * Преобразует пользователя
     *
     * @param Request        $request
     * @param ParamConverter $configuration
     *
     * @return bool
     */
    public function apply(Request $request, ParamConverter $configuration)
    {
        $token = $this->storage->getToken();
        $user  = $token ? $token->getUser() : null;

        if (!$user instanceof User) {
            return false;
        }

        $attribute = $configuration->getName();
        $request->attributes->set($attribute, $user);

        return true;
    }
}
