<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_password_grant\Repository;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\user\UserAuthInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use Drupal\simple_oauth\Entities\UserEntity;

/**
 * The user repository.
 */
class UserRepository implements UserRepositoryInterface {

  /**
   * UserRepository constructor.
   *
   * @param \Drupal\user\UserAuthInterface $userAuth
   *   The service to check the user authentication.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   */
  public function __construct(
    protected UserAuthInterface $userAuth,
    protected EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function getUserEntityByUserCredentials($username, $password, $grantType, ClientEntityInterface $clientEntity) {
    if (empty($username)) {
      return NULL;
    }

    $resolvedUsername = $this->resolveUsername($username);

    // @todo Use authenticateWithFloodProtection when #2825084 lands.
    if ($uid = $this->userAuth->authenticate($resolvedUsername, $password)) {
      $user = new UserEntity();
      $user->setIdentifier($uid);

      return $user;
    }

    return NULL;
  }

  /**
   * Resolves the username if the provided username is an email address.
   *
   * If the given username is an email address, the username is resolved to the
   * account name of the user with that email address. If no account is found
   * with that email address, the username is returned as is.
   *
   * @param string $usernameOrEmail
   *   The username or email address.
   *
   * @return string
   *   The username.
   */
  protected function resolveUsername(string $usernameOrEmail): string {
    // If username contains @, search for user by email first.
    if (strpos($usernameOrEmail, '@') !== FALSE) {
      $accountSearch = \Drupal::entityTypeManager()
        ->getStorage('user')
        ->loadByProperties(['mail' => $usernameOrEmail]);

      /** @var \Drupal\Core\Session\AccountInterface $account */
      if ($account = reset($accountSearch)) {
        return $account->getAccountName();
      }
    }

    return $usernameOrEmail;
  }

}
