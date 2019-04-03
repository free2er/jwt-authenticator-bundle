<?php

declare(strict_types = 1);

namespace Free2er\Jwt\DependencyInjection\Compiler;

use Free2er\Jwt\Authenticator;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Компилятор аутентификатора
 */
class AuthenticatorCompilerPass implements CompilerPassInterface
{
    /**
     * Устанавливает параметры сервис-контейнера
     *
     * @param ContainerBuilder $container
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasAlias(LoggerInterface::class) && !$container->hasDefinition(LoggerInterface::class)) {
            return;
        }

        $authenticator = $container->getDefinition(Authenticator::class);
        $authenticator->addMethodCall('setLogger', [$container->findDefinition(LoggerInterface::class)]);
    }
}
