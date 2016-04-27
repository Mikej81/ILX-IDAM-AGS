var f5 = require('f5-nodejs');
var ldap = require('ldapjs');
var tlsOptions = { 'rejectUnauthorized': false } //NOT recommended for production
var ldap_bind_url = 'ldaps://192.168.2.25:636';  //LDAPS is required for Modify and Create
var ldap_bind_dn = 'CN=F5 Query,OU=Service Accounts,DC=f5lab,DC=com';
var ldap_root_DN = 'DC=f5lab,DC=com';
var ldap_bind_pwd = 'pass@word1';


/* Create a new rpc server for listening to TCL iRule calls. */
var ilx = new f5.ILXServer();

ilx.addMethod('ldap_test', function(req,res) {
        var dn =  req.params()[0].split('\n')[0].replace("dn: ","");
        var sam = '';
        var upn = '';
        var client = ldap.createClient({
        url: ldap_bind_url,
        tlsOptions: tlsOptions
        });
        var ldif_length = req.params()[0].split('\n').length;
        for (var i = 0; i < ldif_length; i++) {
            if (req.params()[0].split('\n')[i].indexOf('sAMAccountName') > -1 ) {
            sam = req.params()[0].split('\n')[i].replace("sAMAccountName: ","").replace("\r","").replace("\n","");
            }
            if (req.params()[0].split('\n')[i].indexOf('userPrincipalName') > -1 ) {
            upn = req.params()[0].split('\n')[i].replace("userPrincipalName: ","").replace("\r","").replace("\n","");
            console.log("UPN: " + upn);
            }
        }
        
        //console.log(req.params()[0]);
        try{
            
            client.bind(ldap_bind_dn, ldap_bind_pwd, function(err) {
              if (err) {
                  console.log(err);
              }
            });
            //Search for values, having issues with case sensitivity
            //var opts = {
                //filter: '(userPrincipalName='+ upn +')',
                //scope: 'sub',
                //attributes: ['name', 'sAMAccountName']
                //};
                //console.log(opts);
                //client.search(ldap_root_DN, opts, function(err, res) {
                  //assert.ifError(err);
                
                 // res.on('searchEntry', function(entry) {
                 //   console.log('entry: ' + JSON.stringify(entry.object));
                 // });
                 // res.on('searchReference', function(referral) {
                 //   console.log('referral: ' + referral.uris.join());
                 // });
                 // res.on('error', function(err) {
                 //   console.error('error: ' + err.message);
                 // });
                 // res.on('end', function(result) {
                 //   console.log('status: ' + result.status);
                 // });
                //});

          client.compare(dn, 'sAMAccountName', sam, function(err, matched) {
                console.log("Comparing: " + dn + " sAMAccountName: " + sam);
                if (err) {
                    console.log(err);
                }
                console.log('matched: ' + matched);
            });

          res.reply("OK");

        } catch(er) {
          res.reply(er);
        }
            client.unbind(function(err) {
              //error
          });
      
});

ilx.addMethod('ldap_modify', function(req,res) {
    var client = ldap.createClient({
        url: ldap_bind_url
        
    });
//    if (ldap_bind_url.startsWith('ldaps')) {
//      var opts = {
//        //how to read in CA PEM
//        ca: [fs.readFileSync('mycacert.pem')]
//    };
//
//    client.starttls(opts, function(err, res) {
//      assert.ifError(err);
//        // Client communication now TLS protected
//    });

//    } else {
      //Create and Modify will fail over unenc-ldap
//    }
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
