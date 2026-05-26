<?php

use dokuwiki\Extension\AuthPlugin;
use dokuwiki\Extension\Event;

/**
 * Provides generic SSO authentication
 * @author Etienne MELEARD <etienne.meleard@renater.fr>
 * @date 2018-08-27
 */

class auth_plugin_genericsso extends AuthPlugin {
    /** @var bool */
    public $success = false;

    private array|null $config = null;
    private array|null $attributes = null;
    private array|null $users = null;
    
    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct();

        $this->cando['external'] = true;
        $this->cando['logout'] = true;

        $this->getConfiguration(); // Checks config
        
        $this->success = true;
    }
    
    /**
     * Get config if valid
     * 
     * @throw Exception
     */
    private function getConfiguration(string $param = null): array|string|null {
        if(!$this->config) {
            global $conf;
            $this->config = $conf['plugin']['genericsso'];
            
            $bad = [];
            foreach([
                'login_url', 'logout_url', 'home_url', 'headers', 'autologin',
                'idp_attribute', 'id_attribute', 'email_attribute', 'fullname_attribute'
            ] as $p) {
                if(!array_key_exists($p, $this->config))
                    $bad[] = $p;
            }
            
            if($bad) {
                msg('Bad configuration for Dokuwiki SSO login : '.implode(', ', $bad), -1);
                return null;
            }
        }
        
        if($param) {
            if(!array_key_exists($param, $this->config)) {
                msg('Unknown configuration parameter for Dokuwiki SSO login : '.$param, -1);
                return null;
            }
            
            return $this->config[$param];
        }
        
        return $this->config;
    }
         
    /**
     * Get attributes if any
     * 
     * @throw Exception
     */
    private function getAttributes(bool $fatal = true, string $attr = null): array|string|null {
        if(is_null($this->attributes)) {
		    $headers = $this->getConfiguration('headers') ? getallheaders() : null;
            
            $this->attributes = [];
            foreach(['idp', 'id', 'email', 'fullname'] as $k) {
                $src = $this->getConfiguration($k.'_attribute');
                if($headers) {
                    $this->attributes[$k] = array_key_exists($src, $headers) ? $headers[$src] : null;
                } else {
                    $this->attributes[$k] = getenv($src);
                }
            }
        }
        
        $bad = array_map(function($k) {
            return $this->getConfiguration($k.'_attribute');
        }, array_keys(array_filter($this->attributes, 'is_null')));
        
        if($bad && $fatal) {
            msg('Missing attribute(s) for Dokuwiki SSO login : '.implode(', ', $bad), -1);
            return [];
        }
        
        if($attr) {
            $v = array_key_exists($attr, $this->attributes) ? $this->attributes[$attr] : null;
            
            if($v)
                return $v;
            
            if($fatal)
                msg('Missing attribute(s) for Dokuwiki SSO login : '.implode(', ', $bad), -1);
                
            return null;
        }
        
        return $this->attributes;
    }
    
    /**
     * Check if any attributes
     */
    private function hasAttributes(string $name = null): bool {
        $attributes = $this->getAttributes(false);
        
        if(is_string($name))
            return array_key_exists($name, $attributes) && !is_null($attributes[$name]);
            
        return count(array_filter($attributes)) > 0;
    }
    
    /**
     * Log info
     */
    private function log(string $msg): void {
        error_log('Dokuwiki SSO plugin: '.$msg);
    }
    
    /**
     * Go to URL
     */
    private function goToUrl(string $url, string $target = ''): void {
        $url = $url ? str_replace('{target}', $target, $url) : $target;
        
        $this->log('redirecting user to '.$url);
        header('Location: '.$url);
        exit;
    }


    /**
     * Check authentication
     *
     * @param string $user
     * @param string $pass
     * @param bool $sticky
     *
     * @throws Exception
     */
    public function trustExternal($user, $pass, $sticky = false): bool {
        $do = array_key_exists('do', $_REQUEST) ? $_REQUEST['do'] : null;
        $autologin = $this->getConfiguration('autologin');
        $hasAttributes = $this->hasAttributes();
	    $hasSession = $this->hasSession();

        $state = ['autologin' => $autologin, 'has_attributes' => $hasAttributes, 'has_session' => $hasSession];
        $state = preg_replace('`(\n|\s+)`', ' ', print_r($state, true));

        if($do === 'login' && !$hasAttributes)
            $this->_login();

        if($do === 'logout' && $hasAttributes)
            $this->_logout();
        
        if($do === 'login' || ($autologin && $hasAttributes && !$hasSession)) {
            $attrs = $this->getAttributes();
            $data = $this->getUserData($user);
            $this->setSession($attrs['id'], $data['grps'], $attrs['email'], $attrs['fullname']);
            $this->log('authenticated user (state='.$state.')');
            return true;
        }
        
        if($do === 'logout' || ($autologin && !$hasAttributes && $hasSession)) {
            $this->dropSession();
            $this->log('logged user out (state='.$state.')');
            return true;
        }
        
        // Check user match is SSO and local session
        if($autologin && $hasSession && $hasAttributes) {
            if($_SESSION[DOKU_COOKIE]['auth']['user'] !== $this->getAttributes(false, 'id')) {
                $this->log('SSO user doesn\'t match local user, logging out (state='.$state.')');
                $this->_logout();
            }
        }
        
        // Refresh from cookie if any
	    auth_login(null, null);
	    return true;
    }
    
    /**
     * Check if local session exists
     */
    private function hasSession(): bool {
        return array_key_exists(DOKU_COOKIE, $_SESSION) && array_key_exists('auth', $_SESSION[DOKU_COOKIE]) && $_SESSION[DOKU_COOKIE]['auth']['user'];
    }

    /**
     * Create user session
     *
     * @throws Exception
     */
    private function setSession(string $user, array $grps = null, string $mail = null, string $name = null): void {
        global $USERINFO;
        global $INPUT;
        
        $USERINFO['name'] = $name ?: $user;
        $USERINFO['mail'] = $mail ?: (mail_isvalid($user) ? $user : null);
        $USERINFO['grps'] = array_filter((array)$grps);

        $INPUT->server->set('REMOTE_USER', $user);

        $secret = auth_cookiesalt(true, true);
        $pass = hash_hmac('sha1', $user, $secret);
        auth_setCookie($user, auth_encrypt($pass, $secret), false);

        $dummy = [];
        Event::createAndTrigger('AUTH_EXTERNAL', $dummy);
    }
    
    /**
     * Remove session data
     */
    private function dropSession(): void {
        auth_logoff();

        $dummy = [];
        Event::createAndTrigger('AUTH_EXTERNAL', $dummy);
    }
    
    /**
     * Redirect for login
     */
    public function _login(): void {
        $this->dropSession();
        $this->goToUrl($this->getConfiguration('login_url'), wl(getId()));
    }
    
    /**
     * Redirect for logout
     */
    public function _logout(): void {
        $this->dropSession();
        $this->goToUrl($this->getConfiguration('logout_url'), $this->getConfiguration('home_url'));
    }

    /**
     * Check password (not used but required by inheritance)
     *
     * @param string $user
     * @param string $pass
     *
     * @throws Exception
     */
    public function checkPass($user, $pass): bool {
        if($_SESSION[DOKU_COOKIE]['auth']['user'] !== $user)
            return false;
        
        $attrs = $this->getAttributes();
        if($user !== $attrs['id'])
            return false;
        
        $secret = auth_cookiesalt(true, true);
        if($pass !== hash_hmac('sha1', $user, $secret))
            return false;
        
        return true;
    }

    /**
     * Get user info
     * 
     * @param string $user
     * @param bool $requireGroups
     */
    public function getUserData($user, $requireGroups = true): array {
        if(is_null($this->users)) {
            $this->users = [];
            if(@file_exists(DOKU_CONF.'users.auth.php')) {
                foreach(file(DOKU_CONF.'users.auth.php') as $line) {
                    $line = trim(preg_replace('/#.*$/', '', $line)); //ignore comments
                    if(!$line) continue;
                    $row = explode(':', $line, 5);
                    $this->users[$row[0]] = [
                        'pass' => $row[1],
                        'name' => urldecode($row[2]),
                        'mail' => $row[3],
                        'grps' => explode(',', $row[4])
                    ];
                }
            }
        }

        // Any user virtualy exists
        $data = ['name' => $user, 'mail' => $user, 'grps' => []];

        global $INPUT;
        if($user === $INPUT->server->str('REMOTE_USER')) {
            $attrs = $this->getAttributes();
            $data = ['name' => $attrs['fullname'], 'mail' => $attrs['email'], 'grps' => []];
        }

        $grps = array_key_exists($user, $this->users) ? $this->users[$user]['grps'] : [];
        $data['grps'] = array_unique(array_merge($grps, $data['grps'], ['session']));

        return $requireGroups ? $data : array_diff_key($data, ['grps' => null]);
    }
}
