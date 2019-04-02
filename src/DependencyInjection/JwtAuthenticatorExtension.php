<?php

declare(strict_types = 1);

namespace Free2er\Jwt\DependencyInjection;

use Free2er\Jwt\Authenticator;
use Free2er\Jwt\User\UserProvider;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;

/**
 * Расширение модуля
 */
class JwtAuthenticatorExtension extends Extension
{
    /**
     * Загружает конфигурацию модуля
     *
     * @param array            $configs
     * @param ContainerBuilder $container
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        $parser    = new Definition(Parser::class);
        $signer    = new Definition($config['algorithm']);
        $publicKey = new Definition(Signer\Key::class, [$config['public_key']]);
        $logger    = $this->getLogger($container);

        $container->setDefinition(UserProvider::class, new Definition(UserProvider::class, [$config['scope_key']]));
        $container->setDefinition(Authenticator::class, new Definition(Authenticator::class, [
            $parser,
            $signer,
            $publicKey,
            $logger,
        ]));
    }

    /**
     * Возвращает логгер
     *
     * @param ContainerBuilder $container
     *
     * @return Definition
     */
    private function getLogger(ContainerBuilder $container): Definition
    {
        if ($container->hasAlias(LoggerInterface::class) || $container->hasDefinition(LoggerInterface::class)) {
            return $container->findDefinition(LoggerInterface::class);
        }

        return new Definition(NullLogger::class);
    }
}
