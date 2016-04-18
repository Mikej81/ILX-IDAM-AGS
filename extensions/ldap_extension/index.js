var f5 = require('f5-nodejs');
var ldap = require('ldapjs');
var ldap_bind_url = 'ldaps://192.168.2.25:636';
var ldap_bind_dn = '';
var ldap_bind_pwd = '';


/* Create a new rpc server for listening to TCL iRule calls. */
var ilx = new f5.ILXServer();

ilx.addMethod('ldap_modify', function(req,res) {
    var client = ldap.createClient({
        url: ldap_bind_url
        
    });
    if (ldap_bind_url.startsWith('ldaps')) {
    	var opts = {
    		//how to read in CA PEM
  			ca: [fs.readFileSync('mycacert.pem')]
		};

		client.starttls(opts, function(err, res) {
  			assert.ifError(err);
  			// Client communication now TLS protected
		});

    } else {
    	//Create and Modify will fail over unenc-ldap
    }
    client.bind(ldap_bind_dn, ldap_bind_pwd, function(err) {
  		assert.ifError(err);
	});
	client.modify('cn=foo, o=example', change, function(err) {
  		assert.ifError(err);
	});
	client.unbind(function(err) {
  		assert.ifError(err);
	});
    
});
ilx.addMethod('ldap_create', function(req,res) {
    var client = ldap.createClient({
        url: ldap_bind_url
        
    });

        if (ldap_bind_url.startsWith('ldaps')) {
    	var opts = {
    		//how to read in CA PEM
  			ca: [fs.readFileSync('mycacert.pem')]
		};

		client.starttls(opts, function(err, res) {
  			assert.ifError(err);
  			// Client communication now TLS protected
		});

    } else {
    	//Create and Modify will fail over unenc-ldap
    }

    client.bind(ldap_bind_dn, ldap_bind_pwd, function(err) {
  		assert.ifError(err);
	});
	client.add('cn=foo, o=example', entry, function(err) {
  		assert.ifError(err);
	});
	client.unbind(function(err) {
  		assert.ifError(err);
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



