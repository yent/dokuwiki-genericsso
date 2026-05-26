<?php

/**
 * Provides generic SSO authentication
 * @author Etienne MELEARD <etienne.meleard@renater.fr>
 * @date 2018-09-19
 */

use dokuwiki\Extension\Event;
use dokuwiki\Extension\EventHandler;
use dokuwiki\Form\Form;

/**
 * Plugin
 */
class action_plugin_genericsso extends DokuWiki_Action_Plugin {
    /**
     * Register listeners
     */
    public function register(EventHandler $controller): void {
        $controller->register_hook('FORM_LOGIN_OUTPUT', 'BEFORE', $this, 'handle');
    }
    
    /**
     * Handle event
     *
     * @param Doku_Event $event
     */
    public function handle(Event $event): void {
        global $lang;
        global $conf;
        global $ID;
        
        if($conf['authtype'] !== 'genericsso')
            return;
        
        /** @var Form $form */
        $form = $event->data;
        while($form->elementCount() != 0)
            $form->removeElement(0);
        
        $form->setHiddenField('id', $ID);
        $form->setHiddenField('do', 'login');
        $form->addButton('', $lang['btn_login'])->attr('type', 'submit');
    }
}
