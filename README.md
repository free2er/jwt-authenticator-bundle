# jwt-authenticator-bundle
JWT Authenticator Bundle

## Installation
This component can be installed with the [Composer](https://getcomposer.org/) dependency manager.

1. [Install Composer](https://getcomposer.org/doc/00-intro.md)

2. Install the component as a dependency of your project

        composer require free2er/jwt-authenticator-bundle

3. Enable the bundle

```php
<?php

// config/bundles.php
return [
    // ...
    Free2er\Jwt\JwtAuthenticatorBundle::class => ['all' => true],
    // ...
];
```

4. Configure the path to the public key

```yml
# config/packages/jwt_authenticator.yaml
jwt_authenticator:
    public_key: file://%kernel.project_dir%/path/to/public.key
```

5. Configure the firewall

```yml
# config/packages/security.yaml
security:
    providers:
        jwt:
            id: Free2er\Jwt\User\UserProvider
    firewalls:
        # ...
        main:
            pattern: ^/api
            stateless: true
            provider: jwt
            guard:
                authenticators:
                    - Free2er\Jwt\Authenticator
        # ...
```

6. Done!
