<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_password_grant\Plugin\Oauth2Grant;

use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\simple_oauth\Plugin\Oauth2GrantBase;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use Psr\Container\ContainerInterface;

/**
 * The password grant plugin.
 *
 * IMPORTANT: This grant should ONLY be used for trusted clients.
 * This grant is not considered secure and should only be used
 * for trusted clients.
 *
 * But it is secure and needed for a good user experience, when used for
 * the primary drupal frontend in decoupled scenarios.
 *
 * @Oauth2Grant(
 *  id = "password",
 *  label = @Translation("Password")
 * )
 */
class Password extends Oauth2GrantBase implements ContainerFactoryPluginInterface {

  /**
   * {@inheritdoc}
   */
  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    protected UserRepositoryInterface $userRepository,
    protected RefreshTokenRepositoryInterface $refreshTokenRepository,
  ) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('simple_oauth_password_grant.repositories.user'),
      $container->get('simple_oauth.repositories.refresh_token'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantType(Consumer $client): GrantTypeInterface {
    $grant = new PasswordGrant($this->userRepository, $this->refreshTokenRepository);

    $refreshTokenTTL = !$client->get('refresh_token_expiration')->isEmpty ? $client->get('refresh_token_expiration')->value : 1209600;
    $duration = new \DateInterval(sprintf('PT%dS', $refreshTokenTTL));

    $grant->setRefreshTokenTTL($duration);

    return $grant;
  }

}
