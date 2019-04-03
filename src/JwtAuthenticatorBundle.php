<?php

declare(strict_types = 1);

namespace Free2er\Jwt;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Модуль аутентификации по ключу JWT
 */
class JwtAuthenticatorBundle extends Bundle
{
    /**
     * Устанавливает параметры сервис-контейнера
     *
     * @param ContainerBuilder $container
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $container->addCompilerPass(new DependencyInjection\Compiler\AuthenticatorCompilerPass());
    }
}
