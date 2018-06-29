<?php
require_once __DIR__."/../src/Users/Users.php";

use \Sarcoma\Users\Users;

class UsersTest extends PHPUnit_Framework_TestCase
{
    public function testValidate()
    {
        $user = new Users();

        $user->setUsername('NewName');
        $user->setEmail('new@email.com');

        $this->assertEmpty($user->validate('Sarcoma', 'email@email.com', 'password'));
        $this->assertArrayHasKey('email', $user->validate('Sarcoma', 'new@email.com', 'password'));
        $this->assertArrayHasKey('email', $user->validate('Sarcoma', '', 'password'));
        $this->assertArrayHasKey('email', $user->validate('Sarcoma', 'notanemail', 'password'));
        $this->assertArrayHasKey('password', $user->validate('Sarcoma', 'email@email.com', ''));
        $this->assertArrayHasKey('password', $user->validate('Sarcoma', 'email@email.com', 'abc'));
        $this->assertArrayHasKey('password',
            $user->validate('Sarcoma', 'email@email.com', str_pad('password', 300, 'abc', STR_PAD_LEFT)));
        $this->assertArrayHasKey('username', $user->validate('', 'email@email.com', 'password'));
        $this->assertArrayHasKey('username', $user->validate('aa', 'email@email.com', 'password'));
        $this->assertArrayHasKey('username', $user->validate('NewName', 'email@email.com', 'password'));
        $this->assertArrayHasKey('username',
            $user->validate(str_pad('username', 300, 'abc', STR_PAD_LEFT), 'email@email.com', 'password'));
    }

    public function testLogin()
    {
        $user = new Users();
        $user->setPasswordHash('password');
        $user->setUsername('Sarcoma');
        $this->assertTrue($user->login('password', $user));
        $this->assertFalse($user->login('wrongpassword', $user));
    }

    public function testAuth()
    {
        $user = new Users();
        $user->setPasswordHash('password');
        $user->setUsername('Sarcoma');
        $this->assertTrue($user->login('password', $user));
        $user->auth('USER', 'USER');
    }

    public function testSetPasswordHash()
    {
        $user = new Users();
        $user->setPasswordHash('password');
        $this->assertNotEmpty($user->getPasswordHash());
    }

}
