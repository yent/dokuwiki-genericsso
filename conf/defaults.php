<?php
/**
 * Settings defaults
 * @author Etienne MELEARD <etienne.meleard@renater.fr>
 * @date 2018-06-27
 */

$conf['autologin'] = false;
$conf['headers'] = false;
$conf['login_url'] = '/sso/login?target={target}';
$conf['logout_url'] = '/sso/login?target={target}';
$conf['home_url'] = '/';
$conf['idp_attribute'] = 'REMOTE_USER';
$conf['id_attribute'] = 'REMOTE_USER';
$conf['email_attribute'] = 'REMOTE_USER';
$conf['fullname_attribute'] = 'REMOTE_USER';
