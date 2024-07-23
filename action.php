<?php

/**
 * Provides generic SSO authentication
 * @author Etienne MELEARD <etienne.meleard@renater.fr>
 * @date 2018-09-19
 */

use dokuwiki\Form\Form;

/**
 * Plugin
 */
class action_plugin_genericsso extends DokuWiki_Action_Plugin {
    /**
     * Register listeners
     * 
     * @param Doku_Event_Handler $controller
     */
    public function register(Doku_Event_Handler $controller) {
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle');
    }
    
    /**
     * Handle event
     * 
     * @param Doku_Event $event
     * @param mixed $param
     */
    public function handle(Doku_Event $event, $param) {
        global $lang;
        global $conf;
        global $ID;
        
        if($conf['authtype'] !== 'genericsso')
            return;
        
        $form = new Form(['id' => 'dw__login']);
        $form->setHiddenField('id', $ID);
        $form->setHiddenField('do', 'login');
        $form->addButton('', $lang['btn_login'])->attr('type', 'submit');

        $event->data = $form;
    }
}
