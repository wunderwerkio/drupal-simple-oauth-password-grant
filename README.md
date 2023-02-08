# Simple OAuth Password Grant

This module re-implements the `PasswordGrant` for the `simple_oauth` module.
For more information about this repository, visit the project page at [https://www.drupal.org/project/simple_oauth_password_grant](https://www.drupal.org/project/simple_oauth_password_grant)

## Usage

To use this module, simply enable the **Password** grant type in your OAuth2 Consumer.
You can then obtain an access token by requesting it with the following payload:

```json
{
  "grant_type": "password",
  "client_id": "__your-client-id__",
  "client_secret": "__your-client-secret__",
  "username": "drupal_username_or_email",
  "password": "drupal_password"
}
```

**Important**  
The username can either be the Drupal username, or the Drupal user's email address!

## Testing

A Test environment can be easily spun-up via [DDEV](https://ddev.readthedocs.io/en/stable/).
The drupal installation is provided by the excellent [DrupalSpoons Composer Plugin](https://gitlab.com/drupalspoons/composer-plugin).

### Start local dev environment

Run the following commands in the project root:

```sh
ddev start
```

To change the drupal version, use 

```sh
ddev change-env
```

### PHPCS

```sh
ddev phpcs
```

### PHPUnit

```sh
ddev phpunit
```
