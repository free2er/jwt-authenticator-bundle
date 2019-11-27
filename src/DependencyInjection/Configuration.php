<?php

declare(strict_types=1);

namespace Free2er\Jwt\DependencyInjection;

use Lcobucci\JWT\Signer\Rsa\Sha512;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Конфигурация модуля
 */
class Configuration implements ConfigurationInterface
{
    /**
     * Возвращает строителя конфигурации
     *
     * @return TreeBuilder
     */
    public function getConfigTreeBuilder()
    {
        $builder = new TreeBuilder('jwt_authenticator');
        $builder->getRootNode()
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('signer')->defaultValue(Sha512::class)->end()
                ->scalarNode('key')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('roles')->defaultValue('roles')->end()
            ->end();

        return $builder;
    }
}
