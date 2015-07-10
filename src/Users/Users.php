<?php

namespace Sarcoma\Users;

/**
 * Class Users
 * @package Sarcoma\Users
 * @Entity @Table(name="users")
 */

class Users
{
    /** @Id @Column(type="integer") @GeneratedValue */
    protected $id;
    /** @Column(type="string") */
    protected $username;
    /** @Column(type="string") */
    protected $email;
    /** @Column(type="string", length=60) */
    protected $password_hash;
    /** @Column(type="string") */
    protected $role;
    /** @Column(type="string", length=64, nullable=true) */
    protected $activation_token;

    /**
     * @return int
     * @codeCoverageIgnore
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return string
     * @codeCoverageIgnore
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @param string $username
     *
     * @codeCoverageIgnore
     */
    public function setUsername($username)
    {
        $this->username = $username;
    }

    /**
     * @return string
     * @codeCoverageIgnore
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @param string $email
     *
     * @codeCoverageIgnore
     */
    public function setEmail($email)
    {
        $this->email = $email;
    }

    /**
     * @return string
     * @codeCoverageIgnore
     */
    public function getPasswordHash()
    {
        return $this->password_hash;
    }

    /**
     * @param string $password
     */
    public function setPasswordHash($password)
    {
        $this->password_hash = password_hash($password, PASSWORD_BCRYPT);
    }

    /**
     * @return string
     * @codeCoverageIgnore
     */
    public function getRole()
    {
        return $this->role;
    }

    /**
     * @param string $role
     *
     * @codeCoverageIgnore
     */
    public function setRole($role = "USER")
    {
        $this->role = $role;
    }

    /**
     * @return string
     * @codeCoverageIgnore
     */
    public function getActivationToken()
    {
        return $this->activation_token;
    }

    /**
     * @param mixed $activation_token
     *
     * @codeCoverageIgnore
     */
    public function setActivationToken($activation_token = false)
    {
        if (!$activation_token) {
            $this->activation_token = bin2hex(openssl_random_pseudo_bytes(32));
        } else {
            $this->activation_token = null;
        }
    }

    /**
     * @param string $username
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function hashUsername($username)
    {
        return hash('sha256', $username);
    }

    /**
     * @param string $username
     * @param string $email
     * @param string $password
     *
     * @return mixed
     */
    public function validate($username, $email, $password)
    {

        $error = array();

        if (!empty($email)) {
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error['email'] = 'Invalid Email';
            }
            if ($email == $this->email) {
                $error['email'] = 'Email address is already registered';
            }
        } else {
            $error['email'] = 'You must enter your email address';
        }

        if (!empty($password)) {
            if (mb_strlen($password) < 8) {
                $error['password'] = 'Password must contain 8+ characters';
            } elseif (mb_strlen($password) > 255) {
                $error['password'] = 'Password is too long';
            }
        } else {
            $error['password'] = 'You must enter a password';
        }

        if (!empty($username)) {
            if (mb_strlen($username) < 4) {
                $error['username'] = 'Username must contain 4+ characters';
            } elseif (mb_strlen($username) > 255) {
                $error['username'] = 'Username too long';
            }
            if ($username == $this->username) {
                $error['username'] = 'Username is already registered';
            }
        } else {
            $error['username'] = 'You must enter a username';
        }

        return $error;
    }

    /**
     * @param string $password
     * @param object $userObject
     *
     * @return bool
     */
    public static function login($password, $userObject)
    {
        if (password_verify($password, $userObject->getPasswordHash())) {
            session_regenerate_id(true);
            $_SESSION['username'] = $userObject->getUsername();
            $_SESSION['time-out'] = time() + 604800;

            return true;
        }

        return false;
    }

    /**
     * @param string $user_role
     * @param string $role
     *
     * @return bool
     */
    public static function auth($user_role, $role)
    {
        return (($user_role == $role) && ($_SESSION['time-out'] > time())) ? true : false;
    }

    /**
     * @codeCoverageIgnore
     */
    public static function logout()
    {
        $_SESSION = array();
        session_destroy();
        setcookie(session_name(), '', time() - 300);
    }

    // ToDo: Send Password reset request
    // ToDo: Reset password
}
