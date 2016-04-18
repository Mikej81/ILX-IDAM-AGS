#
# A "Hello World" template for iRulesLX RPC.
#
# Note: This example works in concert with the template in an
# extension's default index.js.
#
# To use, replace every item in <> with an appropriate value.
#
# when <EVENT> {
#    # Get a handle to the running extension instance to call into.
#    set RPC_HANDLE [ILX::init <PLUGIN_NAME> <EXTENSION_NAME>]
#    # Make the call and store the response in $rpc_response
#    set rpc_response [ILX::call $RPC_HANDLE <REMOTE_FUNC_NAME> <ARG> <ARG> ...  ]
# }
when ACCESS_POLICY_AGENT_EVENT {

set ldap_handle [ILX::init ldap extension]
set ldap_ldif_data {}
set ldap_ldif_changetype ''
set ldap_user_dn_suffix 'OU=Lab Users,DC=f5lab,DC=com'

     switch [ACCESS::policy agent_id] {
        "ldap_create" {
        	#do some LDIF generation magic
        	append ldap_ldif_data "dn: [table lookup -notouch -subtable $table_name dn]\r\n"
        	append ldap_ldif_data "changetype: add\r\n"
        	append ldap_ldif_data "cn: [table lookup -notouch -subtable $table_name cn]\r\n"
        	append ldap_ldif_data "sAMAccountName: $table_name\r\n"
        	append ldap_ldif_data "userPrincipalName: [table lookup -notouch -subtable $table_name upn]\r\n"
        	append ldap_ldif_data "\r\n"
        	#Required for set password
        	append ldap_ldif_data "dn: [table lookup -notouch -subtable $table_name dn]\r\n"
        	append ldap_ldif_data "changetype: modify\r\n"
        	append ldap_ldif_data "replace: unicodePwd\r\n"
        	#Sets password to pass@word1
        	append ldap_ldif_data "unicodePwd:: IgBBAG4ARQB4AGEAbQBwAGwAZQBQAGEAcwBzAHcAbwByAGQAMQAhACIA\r\n"
        	append ldap_ldif_data "\r\n"
        	append ldap_ldif_data "dn: [table lookup -notouch -subtable $table_name dn]\r\n"
        	append ldap_ldif_data "changetype: modify\r\n"
        	#Required for creating new user
        	append ldap_ldif_data "replace: userAccountControl\r\n"
        	append ldap_ldif_data "userAccountControl: 512\r\n"
        	#EOF
        	append ldap_ldif_data "-"

        	set ldap_response [ILX::call $ldap_handle ldap_create $ldap_ldif_data ]}
        "ldap_modify" {
        	append ldap_ldif_data "dn: [table lookup -notouch -subtable $table_name dn]\r\n"
        	append ldap_ldif_data "changetype: modify\r\n"

        	set ldap_response [ILX::call $ldap_handle ldap_modify $ldap_ldif_data ]}
        "ldif_create" {
        	append ldap_ldif_data "dn: [table lookup -notouch -subtable $table_name dn]\r\n"
        	append ldap_ldif_data "changetype: add\r\n"
        	append ldap_ldif_data "objectClass: user\r\n"   
        	append ldap_ldif_data "cn: [table lookup -notouch -subtable $table_name cn]\r\n"
        	append ldap_ldif_data "sAMAccountName: $table_name\r\n"
        	append ldap_ldif_data "userPrincipalName: [table lookup -notouch -subtable $table_name upn]\r\n"
        	append ldap_ldif_data "\r\n"
        	#Required for set password
        	append ldap_ldif_data "dn: [table lookup -notouch -subtable $table_name dn]\r\n"
        	append ldap_ldif_data "changetype: modify\r\n"
        	append ldap_ldif_data "replace: unicodePwd\r\n"
        	append ldap_ldif_data "unicodePwd:: IgBBAG4ARQB4AGEAbQBwAGwAZQBQAGEAcwBzAHcAbwByAGQAMQAhACIA\r\n"
        	append ldap_ldif_data "\r\n"
        	append ldap_ldif_data "dn: [table lookup -notouch -subtable $table_name dn]\r\n"
        	append ldap_ldif_data "changetype: modify\r\n"
        	#Required for creating new user
        	append ldap_ldif_data "replace: userAccountControl\r\n"
        	append ldap_ldif_data "userAccountControl: 512\r\n"
        	#EOF
        	append ldap_ldif_data "-"
        }
        "CERTPROC" {
        	if { [ACCESS::session data get session.ssl.cert.x509extension] contains "othername:UPN<" } {
        		set tmpupn [findstr [ACCESS::session data get session.ssl.cert.x509extension] "othername:UPN<" 14 ">"]
        		ACCESS::session data set session.custom.certupn $tmpupn
        		log local0. "Extracted EDIPI: $tmpupn"
	        }
	        if { [ACCESS::session data get session.ssl.cert.x509extension] contains "email:" } {
	          set tmpemail [findstr [ACCESS::session data get session.ssl.cert.x509extension] "email:" 6 ","]
	          ACCESS::session data set session.custom.email $tmpemail
	          log local0. "Extracted Email Field: $tmpemail"
	        }
	        if { [ACCESS::session data get session.ssl.cert.subject] contains "CN="} {
	         set tmpcn [findstr [ACCESS::session data get session.ssl.cert.subject] "CN=" 3 ,]
	         ACCESS::session data set session.custom.tmpcn $tmpcn
	         log local0. "Extracted CN: $tmpcn"
	        }
	        if { [ACCESS::session data get session.ssl.cert.subject] contains "C="} {
	         set tmpc [findstr [ACCESS::session data get session.ssl.cert.subject] "C=" 2 ,]
	         ACCESS::session data set session.custom.country $tmpc
	         log local0. "Extracted Country: $tmpc"
	        }
	        if { [ACCESS::session data get session.ssl.cert.subject] contains "O="} {
	         set tmpo [findstr [ACCESS::session data get session.ssl.cert.subject] "O=" 2 ,]
	         ACCESS::session data set session.custom.org $tmpo
	         log local0. "Extracted Org: $tmpo"
	        }
        #Figure out how to pull validity / expiration dates
        if { [ACCESS::session data get session.ssl.cert.end] ne ""} {
         set expire [ACCESS::session data get session.ssl.cert.end]
         ACCESS::session data set session.custom.expiration $expire
        }
        if { [ACCESS::session data get session.ssl.cert.subject] ne ""} {
        set data [ACCESS::session data get "session.ssl.cert.subject"]
        set commonName [findstr $data "CN=" 3 ","]
        set cert_list [split $data ","]
        scan $commonName {%[^\.].%[^\.].%[^\.].%[^\.].%[^\.]} last first middle suffix edipinum
        log local0. "CommonName for Scan: $commonName"
        if { [info exists edipinum] } {
          log local0. "Suffix is $suffix"
          log local0. "EDIPI is $edipinum"
          ACCESS::session data set session.custom.edipinum $edipinum
        } elseif { [info exists suffix] } {
          ACCESS::session data set session.custom.edipinum $suffix
          log local0. "EDIPI is $suffix"
          }
          elseif { [info exists middle] } {
            ACCESS::session data set session.custom.edipinum $middle
            log local0. "EDIPI is $middle"
          }
            ACCESS::session data set session.custom.common $commonName
            ACCESS::session data set session.custom.lastname $last
            ACCESS::session data set session.custom.firstname $first
            #log local0. "Creating SFDC User: $commonName, $last, $first, $tmpemail"
            set log_email [ACCESS::session data get session.custom.email]
            set log_edipi [ACCESS::session data get session.custom.edipinum]
            #log local0. "SFDC Federated User Data: IDPName: $log_email, NameID: $log_edipi"
        }
        }
     }
}







