var f5 = require('f5-nodejs');
var ldap = require('ldapjs');
var tlsOptions = { 'rejectUnauthorized': false } //NOT recommended for production
var ldap_bind_url = 'ldaps://192.168.2.25:636';  //LDAPS is required for Modify and Create
var ldap_bind_dn = 'CN=F5 Query,OU=Service Accounts,DC=f5lab,DC=com';
var ldap_root_DN = 'DC=f5lab,DC=com';
var ldap_bind_pwd = 'pass@word1';

var ilx = new f5.ILXServer();

ilx.addMethod('ldap_test', function(req,res) {
        var client = ldap.createClient({
        url: ldap_bind_url,
        tlsOptions: tlsOptions
        });

        var accountJson = JSON.parse(req.params()[0]);
        //DN and CN are flipped for creating new accounts in a specific OU
        //USE CN for existing DN pulled from Certificate
        var dn = accountJson["dn"];
        var cn = accountJson["cn"];
        var upn = accountJson["userPrincipalName"];
        var sam = accountJson["sAMAccountName"];
        var otpPass = accountJson["otp_pass"];

        try{
            
            client.bind(ldap_bind_dn, ldap_bind_pwd, function(err) {
              if (err) {
                  console.log(err);
              }
            });
            
          client.compare(cn, 'sAMAccountName', sam, function(err, matched) {
                //console.log("Comparing: " + dn + " sAMAccountName: " + sam);
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


ilx.listen();
