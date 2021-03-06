var f5 = require('f5-nodejs');
var ldap = require('ldapjs');

var AuthenticationContext = require('adal-node').AuthenticationContext;
//ADAL Options
var clientId = 'yourClientIdHere';
var clientSecret = 'yourAADIssuedClientSecretHere'
var authorityHostUrl = 'https://login.windows.net';
var tenant = 'myTenant';
var authorityUrl = authorityHostUrl + '/' + tenant;
var redirectUri = 'http://localhost:3000/getAToken';
var resource = '00000002-0000-0000-c000-000000000000';
var templateAuthzUrl = 'https://login.windows.net/' + 
                        tenant + 
                        '/oauth2/authorize?response_type=code&client_id=' +
                        clientId + 
                        '&redirect_uri=' + 
                        redirectUri + 
                        '&state=<state>&resource=' + 
                        resource;

//LDAPJS Options                        
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

        var encodedPassbuff = new Buffer('"' + otpPass + '"', 'utf16le');
        var encodedPass = encodedPassbuff.toString('base64');

        try{
            
            client.bind(ldap_bind_dn, ldap_bind_pwd, function(err) {
              if (err) {
                  console.log(err);
              }
            });
            
          client.compare(cn, 'sAMAccountName', sam, function(err, matched) {
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
  var changetype = accountJson["changetype"];
  var changeAttr = accountJson["attribute"];
  var changeAttrVal = '';
  var modification = '';
  if ((changetype == 'replace')&&(changeAttr == 'password')){
    var utf8_pass = "\"" + otpPass + "\"";
    console.log("PLAIN PASS: " + otpPass);
    var buff_pass = new Buffer(utf8_pass, 'utf16le');
    var enc_pass = buff_pass.toString();
    
    mods = new ldap.Change({
      operation: 'replace', modification: { unicodePwd: enc_pass } });

  }

  client.bind(ldap_bind_dn, ldap_bind_pwd, function(err) {
    if (err) {
        console.log(err);
    }
  });

try {

  client.modify(cn, mods, function(err) {
    if (err) {
        console.log(err);
      }
        console.log("Modified: "+ cn);
  });
} catch(er) {
            res.reply(er);
            console.log("error: " + er);
}
  client.unbind(function(err) {
    if (err) {
        console.log(err);
    }
  });

  res.reply("OK");

});
ilx.addMethod('ldap_create', function(req,res) {
    var client = ldap.createClient({
        url: ldap_bind_url
        
    });

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

function encodePassword(password) {
  //console.log(password);
    return new Buffer('"' + password + '"', 'utf16le').toString();
}


ilx.listen();