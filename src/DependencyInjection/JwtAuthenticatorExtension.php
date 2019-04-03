<?php

declare(strict_types = 1);

namespace Free2er\Jwt\DependencyInjection;

use Free2er\Jwt\Authenticator;
use Free2er\Jwt\User\UserProvider;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
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

        $container->setDefinition(UserProvider::class, new Definition(UserProvider::class, [$config['scope_key']]));
        $container->setDefinition(Authenticator::class, new Definition(Authenticator::class, [
            $parser,
            $signer,
            $publicKey,
        ]));
    }
}
