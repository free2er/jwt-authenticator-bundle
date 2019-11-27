<?php

declare(strict_types=1);

namespace Free2er\Jwt\DependencyInjection;

use Lcobucci\JWT\Signer\Key;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Throwable;

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
     *
     * @throws Throwable
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        $container->setDefinition('jwt_authenticator.signer', new Definition($config['signer']));
        $container->setDefinition('jwt_authenticator.key', new Definition(Key::class, [$config['key']]));
        $container->setParameter('jwt_authenticator.roles', $config['roles']);

        $loader = new YamlFileLoader($container, new FileLocator(dirname(__DIR__) . '/Resources/config'));
        $loader->load('services.yaml');
    }
}
