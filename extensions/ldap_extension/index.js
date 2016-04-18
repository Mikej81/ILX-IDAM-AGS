var f5 = require('f5-nodejs');
var ldap = require('ldapjs');

/* Create a new rpc server for listening to TCL iRule calls. */
var ilx = new f5.ILXServer();

ilx.addMethod('ldap_modify', function(req,res) {
    var client = ldap.createClient({
        url: 'ldaps://192.168.2.25:636'
        
    });
    
    
});
ilx.addMethod('ldap_create', function(req,res) {
    var client = ldap.createClient({
        url: 'ldaps://192.168.2.25:636'
        
    });
    
    
});

/*
 * ilx.addMethod('<REMOTE_FUNC_NAME>', function(req, res) {
 *   // Function parameters can be found in req.params().
 *   console.log('params: ' + req.params());
 *   // Whatever is placed in res.reply() will be the return value from ILX::call.
 *   res.reply('<RESPONSE>');
 * });
 */

/* Start listening for ILX::call and ILX::notify events. */
ilx.listen();



