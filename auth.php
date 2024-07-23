<?php

use dokuwiki\Extension\Event;
use JetBrains\PhpStorm\NoReturn;

/**
 * Provides generic SSO authentication
 * @author Etienne MELEARD <etienne.meleard@renater.fr>
 * @date 2018-08-27
 */

class auth_plugin_genericsso extends DokuWiki_Auth_Plugin {
    /** @var bool */
    public $success = false;

    /**
     * Possible things an auth backend module may be able to
     * do. The things a backend can do need to be set to true
     * in the constructor.
     * 
     * @var array
     */
    protected $cando = [
        'addUser'      => false, // can Users be created?
        'delUser'      => false, // can Users be deleted?
        'modLogin'     => false, // can login names be changed?
        'modPass'      => false, // can passwords be changed?
        'modName'      => false, // can real names be changed?
        'modMail'      => false, // can emails be changed?
        'modGroups'    => false, // can groups be changed?
        'getUsers'     => false, // can a (filtered) list of users be retrieved?
        'getUserCount' => false, // can the number of users be retrieved?
        'getGroups'    => false, // can a list of available groups be retrieved?
        'external'     => true,  // does the module do external auth checking?
        'logout'       => true,  // can the user logout again? (eg. not possible with HTTP auth)
    ];
    
    private array|null $_conf = null;
    private array|null $_attrs = null;
    private array|null $_users = null;
    
    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct();

        $this->_getConf(); // Checks config
        
        $this->success = true;
    }
    
    /**
     * Get config if valid
     * 
     * @throw Exception
     */
    private function _getConf(string $param = null): array|string|null {
        if(!$this->_conf) {
            global $conf;
            $this->_conf = $conf['plugin']['genericsso'];
            
            $bad = [];
            foreach([
                'login_url', 'logout_url', 'home_url', 'headers', 'autologin',
                'idp_attribute', 'id_attribute', 'email_attribute', 'fullname_attribute'
            ] as $p) {
                if(!array_key_exists($p, $this->_conf))
                    $bad[] = $p;
            }
            
            if($bad) {
                msg('Bad configuration for Dokuwiki SSO login : '.implode(', ', $bad), -1);
                return null;
            }
        }
        
        if($param) {
            if(!array_key_exists($param, $this->_conf)) {
                msg('Unknown configuration parameter for Dokuwiki SSO login : '.$param, -1);
                return null;
            }
            
            return $this->_conf[$param];
        }
        
        return $this->_conf;
    }
         
    /**
     * Get attributes if any
     * 
     * @throw Exception
     */
    private function _getAttributes(bool $fatal = true, string $attr = null): array|null {
        if(is_null($this->_attrs)) {
            $headers = $this->_getConf('headers') ? getallheaders() : null;
            
            $this->_attrs = [];
            foreach(['idp', 'id', 'email', 'fullname'] as $k) {
                $src = $this->_getConf($k.'_attribute');
                if($headers) {
                    $this->_attrs[$k] = array_key_exists($src, $headers) ? $headers[$src] : null;
                } else {
                    $this->_attrs[$k] = getenv($src);
                }
            }
        }
        
        $bad = array_map(function($k) {
            return $this->_getConf($k.'_attribute');
        }, array_keys(array_filter($this->_attrs, 'is_null')));
        
        if($bad && $fatal) {
            msg('Missing attribute(s) for Dokuwiki SSO login : '.implode(', ', $bad), -1);
            return [];
        }
        
        if($attr) {
            $v = array_key_exists($attr, $this->_attrs) ? $this->_attrs[$attr] : null;
            
            if($v)
                return $v;
            
            if($fatal)
                msg('Missing attribute(s) for Dokuwiki SSO login : '.implode(', ', $bad), -1);
                
            return null;
        }
        
        return $this->_attrs;
    }
    
    /**
     * Check if any attributes
     */
    private function _hasAttributes(string $attr = null): bool {
        $attrs = $this->_getAttributes(false);
        
        if(is_string($attr))
            return array_key_exists($attr, $attrs) && !is_null($attrs[$attr]);
            
        return count(array_filter($this->_attrs)) > 0;
    }
    
    /**
     * Log info
     */
    private function _log(string $msg): void {
        error_log('Dokuwiki SSO plugin: '.$msg);
    }
    
    /**
     * Go to URL
     */
    #[NoReturn] private function _goto(string $url, string $target = ''): void {
        $url = $url ? str_replace('{target}', $target, $url) : $target;
        
        $this->_log('redirecting user to '.$url);
        header('Location: '.$url);
        exit;
    }
    
    
    /**
     * Check authentication
     * 
     * @param string $user
     * @param string $pass
     * @param bool $sticky
     */
    public function trustExternal($user, $pass, $sticky = false) {
        $do = array_key_exists('do', $_REQUEST) ? $_REQUEST['do'] : null;
        $autologin = $this->_getConf('autologin');
        $has_attributes = $this->_hasAttributes();
        $has_session = $this->_hasSession();

        $state = ['autologin' => $autologin, 'has_attributes' => $has_attributes, 'has_session' => $has_session];
        $state = preg_replace('`(\n|\s+)`', ' ', print_r($state, true));

        if($do === 'login' && !$has_attributes)
            $this->_login();

        if($do === 'logout' && $has_attributes)
            $this->_logout();
        
        if($do === 'login' || ($autologin && $has_attributes && !$has_session)) {
            $attrs = $this->_getAttributes();
            $data = $this->getUserData($user);
            $this->_setSession($attrs['id'], $data['grps'], $attrs['email'], $attrs['fullname']);
            $this->_log('authenticated user (state='.$state.')');
            return;
        }
        
        if($do === 'logout' || ($autologin && !$has_attributes && $has_session)) {
            $this->_dropSession();
            $this->_log('logged user out (state='.$state.')');
            return;
        }
        
        // Check user match is SSO and local session
        if($autologin && $has_session && $has_attributes) {
            if($_SESSION[DOKU_COOKIE]['auth']['user'] !== $this->_getAttributes(false, 'id')) {
                $this->_log('SSO user doesn\'t match local user, logging out (state='.$state.')');
                $this->_logout();
            }
        }
        
        // Refresh from cookie if any
        auth_login(null, null);
    }
    
    /**
     * Check if local session exists
     */
    private function _hasSession(): bool {
        return array_key_exists(DOKU_COOKIE, $_SESSION) && array_key_exists('auth', $_SESSION[DOKU_COOKIE]) && $_SESSION[DOKU_COOKIE]['auth']['user'];
    }
    
    /**
     * Create user session
     */
    private function _setSession(string $user, array $grps = null, string $mail = null, string $name = null): void {
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
        trigger_event('AUTH_EXTERNAL', $dummy);
    }
    
    /**
     * Remove session data
     */
    private function _dropSession(): void {
        auth_logoff();

        $dummy = [];
        trigger_event('AUTH_EXTERNAL', $dummy);
    }
    
    /**
     * Redirect for login
     */
    #[NoReturn] public function _login(): void {
        $this->_dropSession();
        $this->_goto($this->_getConf('login_url'), wl(getId()));
    }
    
    /**
     * Redirect for logout
     */
    #[NoReturn] public function _logout(): void {
        $this->_dropSession();
        $this->_goto($this->_getConf('logout_url'), $this->_getConf('home_url'));
    }
    
    /**
     * Check password (not used but required by inheritance)
     * 
     * @param string $user
     * @param string $pass
     */
    public function checkPass($user, $pass): bool {
        if($_SESSION[DOKU_COOKIE]['auth']['user'] !== $user)
            return false;
        
        $attrs = $this->_getAttributes();
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
        if(is_null($this->_users)) {
            $this->_users = [];
            if(@file_exists(DOKU_CONF.'users.auth.php')) {
                foreach(file(DOKU_CONF.'users.auth.php') as $line) {
                    $line = trim(preg_replace('/#.*$/', '', $line)); //ignore comments
                    if(!$line) continue;
                    $row = explode(':', $line, 5);
                    $this->_users[$row[0]] = [
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
            $attrs = $this->_getAttributes();
            $data = ['name' => $attrs['fullname'], 'mail' => $attrs['email'], 'grps' => []];
        }

        $grps = array_key_exists($user, $this->_users) ? $this->_users[$user]['grps'] : [];
        $data['grps'] = array_unique(array_merge($grps, $data['grps'], ['session']));

        return $requireGroups ? $data : array_diff_key($data, ['grps' => null]);
    }
}
