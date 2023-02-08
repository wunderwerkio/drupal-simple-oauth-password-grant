<?php

declare(strict_types=1);

namespace Drupal\Tests\simple_oauth_password_grant\Kernel;

use Drupal\Tests\simple_oauth\Kernel\AuthorizedRequestBase as Base;

/**
 * Class RequestBase.
 *
 * Base class that handles common logic and config for the authorized requests.
 */
abstract class AuthorizedRequestBase extends Base {

  /**
   * The user password.
   *
   * @var string
   */
  protected $password;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'consumers',
    'file',
    'image',
    'options',
    'serialization',
    'system',
    'simple_oauth',
    'simple_oauth_test',
    'user',
    'simple_oauth_password_grant',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installConfig(['simple_oauth_password_grant']);

    $this->password = $this->randomString(12);
    $this->user
      ->setPassword($this->password)
      ->setEmail('test@example.com')
      ->save();

    $grantTypes = [
      ['value' => 'password'],
      ['value' => 'refresh_token'],
    ];
    $this->client
      ->set('grant_types', $grantTypes)
      ->save();

    // Update scopes.
    foreach (explode(' ', $this->scope) as $name) {
      $result = \Drupal::entityTypeManager()->getStorage('oauth2_scope')->loadByProperties(['name' => $name]);
      /** @var \Drupal\simple_oauth\Entity\Oauth2Scope $scope */
      $scope = reset($result);

      if (!$scope) {
        throw new \Exception(sprintf('Scope %s not found', $name));
      }

      $grantTypes = $scope->get('grant_types');
      $grantTypes['password'] = [
        'status' => TRUE,
        'description' => 'Test scope 1 description password',
      ];

      $scope->set('grant_types', $grantTypes)->save();
    }
  }

}
