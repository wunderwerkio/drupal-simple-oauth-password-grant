<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_password_grant\Repository;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\user\UserAuthInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use Drupal\simple_oauth\Entities\UserEntity;
use Symfony\Component\HttpFoundation\RequestStack;

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
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service.
   * @param \Drupal\Core\Http\RequestStack $requestStack
   *   The request stack.
   */
  public function __construct(
    protected UserAuthInterface $userAuth,
    protected EntityTypeManagerInterface $entityTypeManager,
    protected ConfigFactoryInterface $configFactory,
    protected FloodInterface $flood,
    protected RequestStack $requestStack,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function getUserEntityByUserCredentials($username, $password, $grantType, ClientEntityInterface $clientEntity) {
    $floodConfig = $this->configFactory->get('user.flood');
    $request = $this->requestStack->getCurrentRequest();

    // This is taken from the basic_auth module.
    // @see \Drupal\basic_auth\Authentication\Provider\BasicAuth::authenticate()
    // Do not allow any login from the current user's IP if the limit has been
    // reached. Default is 50 failed attempts allowed in one hour. This is
    // independent of the per-user limit to catch attempts from one IP to log
    // in to many different user accounts.  We have a reasonably high limit
    // since there may be only one apparent IP for all users at an institution.
    if ($this->flood->isAllowed('oauth2_password_grant.failed_login_ip', $floodConfig->get('ip_limit'), $floodConfig->get('ip_window'))) {
      $account = $this->getAccount($username);
      if ($account) {
        if ($floodConfig->get('uid_only')) {
          // Register flood events based on the uid only, so they apply for any
          // IP address. This is the most secure option.
          $identifier = $account->id();
        }
        else {
          // The default identifier is a combination of uid and IP address. This
          // is less secure but more resistant to denial-of-service attacks that
          // could lock out all users with public user names.
          $identifier = $account->id() . '-' . $request->getClientIP();
        }

        // Don't allow login if the limit for this user has been reached.
        // Default is to allow 5 failed attempts every 6 hours.
        if ($this->flood->isAllowed('oauth2_password_grant.failed_login_user', $floodConfig->get('user_limit'), $floodConfig->get('user_window'), $identifier)) {
          // @todo Use authenticateWithFloodProtection when #2825084 lands.
          $uid = $this->userAuth->authenticate($account->getAccountName(), $password);

          if ($uid) {
            $this->flood->clear('oauth2_password_grant.failed_login_user', $identifier);

            $user = new UserEntity();
            $user->setIdentifier($uid);

            return $user;
          }
          else {
            // Register a per-user failed login event.
            $this->flood->register('oauth2_password_grant.failed_login_user', $floodConfig->get('user_window'), $identifier);
          }
        }
      }
    }

    // Always register an IP-based failed login event.
    $this->flood->register('oauth2_password_grant.failed_login_ip', $floodConfig->get('ip_window'));

    return NULL;
  }

  /**
   * Get an active account by username or email.
   *
   * @param string $usernameOrEmail
   *   The username or email address.
   *
   * @return \Drupal\Core\Session\AccountInterface|null
   *   The account or NULL if not found.
   */
  protected function getAccount(string $usernameOrEmail): ?AccountInterface {
    // If username contains @, search for user by email first.
    if (strpos($usernameOrEmail, '@') !== FALSE) {
      $account = $this->getAccountByProperty('mail', $usernameOrEmail);
      if ($account) {
        return $account;
      }
    }

    return $this->getAccountByProperty('name', $usernameOrEmail);
  }

  /**
   * Get an active account by property.
   *
   * @param string $property
   *   The property to search for.
   * @param string $value
   *   The value to search for.
   *
   * @return \Drupal\Core\Session\AccountInterface|null
   *   The account or NULL if not found.
   */
  protected function getAccountByProperty(string $property, string $value): ?AccountInterface {
    $accountSearch = \Drupal::entityTypeManager()
      ->getStorage('user')
      ->loadByProperties([$property => $value, 'status' => 1]);

    /** @var \Drupal\Core\Session\AccountInterface $account */
    if ($account = reset($accountSearch)) {
      return $account;
    }

    return NULL;
  }

}
