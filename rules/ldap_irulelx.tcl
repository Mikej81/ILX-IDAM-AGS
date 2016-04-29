when ACCESS_POLICY_AGENT_EVENT {

set ldap_handle [ILX::init ldap_extension]
set ldap_ldif_data {}
set ldap_ldif_changetype ""
set ldap_user_dn_suffix "OU=Lab Users,DC=f5lab,DC=com"

     switch [ACCESS::policy agent_id] {
        "ldap_create" {
            #do some LDIF generation magic
            append ldap_ldif_data "dn: [ACCESS::session data get session.custom.idam.dn]\r\n"
            append ldap_ldif_data "changetype: add\r\n"
            append ldap_ldif_data "cn: [ACCESS::session data get session.custom.idam.cn]\r\n"
            append ldap_ldif_data "sAMAccountName: [ACCESS::session data get session.custom.idam.sam]\r\n"
            append ldap_ldif_data "userPrincipalName: [ACCESS::session data get session.custom.idam.upn]\r\n"
            append ldap_ldif_data "\r\n"
            #Required for set password
            append ldap_ldif_data "dn: [ACCESS::session data get session.custom.idam.dn]\r\n"
            append ldap_ldif_data "changetype: modify\r\n"
            append ldap_ldif_data "replace: unicodePwd\r\n"
            #Sets password to pass@word1
            append ldap_ldif_data "unicodePwd:: IgBBAG4ARQB4AGEAbQBwAGwAZQBQAGEAcwBzAHcAbwByAGQAMQAhACIA\r\n"
            append ldap_ldif_data "\r\n"
            append ldap_ldif_data "dn: [ACCESS::session data get session.custom.idam.dn]\r\n"
            append ldap_ldif_data "changetype: modify\r\n"
            #Required for creating new user
            append ldap_ldif_data "replace: userAccountControl\r\n"
            append ldap_ldif_data "userAccountControl: 512\r\n"
            #EOF
            append ldap_ldif_data "-"

            set ldap_response [ILX::call $ldap_handle ldap_create $ldap_ldif_data ]
          }
        "ldap_modify" {
          #Collect some data for modifications, Test changes password
            expr srand([clock clicks])
            set tmpKey [CRYPTO::keygen -alg random -len 128 -passphrase [AES::key 128] -rounds 2]
            set otp "<M@8ty[string toupper [string range [b64encode $tmpKey] 0 16]]>"
            append ldap_ldif_data "{"
            append ldap_ldif_data "\"dn\": \"[ACCESS::session data get session.custom.idam.dn]\","
            append ldap_ldif_data "\"cn\": \"[ACCESS::session data get session.custom.idam.fullcn]\","
            append ldap_ldif_data "\"changetype\": \"replace\","
            append ldap_ldif_data "\"attribute\": \"password\","
            append ldap_ldif_data "\"otp_pass\": \"$otp\""
            append ldap_ldif_data "}"

            set ldap_response [ILX::call $ldap_handle ldap_modify $ldap_ldif_data ]
            log local0. $ldap_response
          }
        "ldif_create" {
          #test otp generate for random password
          expr srand([clock clicks])
          set tmpKey [CRYPTO::keygen -alg random -len 128 -passphrase [AES::key 128] -rounds 2]
          set otp "<M@8ty[string toupper [string range [b64encode $tmpKey] 0 16]]>"
          #set otp "<M@8t[string range [format "%08d" [expr int(rand() * 1e9)]] 1 16 ]"
          #this is just a test to collect the data from CERTPROC
            #change string to JSON
            append ldap_ldif_data "{"
            append ldap_ldif_data "\"dn\": \"[ACCESS::session data get session.custom.idam.dn]\","
            append ldap_ldif_data "\"changetype\": \"add\","
            append ldap_ldif_data "\"objectClass\": \"user\","   
            append ldap_ldif_data "\"cn\": \"[ACCESS::session data get session.custom.idam.fullcn]\","
            append ldap_ldif_data "\"sAMAccountName\": \"[ACCESS::session data get session.custom.idam.sam]\","
            append ldap_ldif_data "\"userPrincipalName\": \"[ACCESS::session data get session.custom.idam.upn]\","
            #Required for set password
            append ldap_ldif_data "\"dn\": \"[ACCESS::session data get session.custom.idam.dn]\","
            append ldap_ldif_data "\"changetype\": \"modify\","
            append ldap_ldif_data "\"replace\": \"unicodePwd\","
            append ldap_ldif_data "\"password\": \"unicodePwd:: IgBBAG4ARQB4AGEAbQBwAGwAZQBQAGEAcwBzAHcAbwByAGQAMQAhACIA\","
            append ldap_ldif_data "\"otp_pass\": \"$otp\","

            append ldap_ldif_data "\"dn\": \"[ACCESS::session data get session.custom.idam.dn]\","
            append ldap_ldif_data "\"changetype\": \"modify\","
            #Required for creating new user
            append ldap_ldif_data "\"replace\": \"userAccountControl\","
            append ldap_ldif_data "\"userAccountControl\": \"512\""
            #EOF
            append ldap_ldif_data "}"
            #log local0. $ldap_ldif_data
            set ldap_response [ILX::call $ldap_handle ldap_test $ldap_ldif_data]
        }
        "CERTPROC" {
            if { [ACCESS::session data get session.ssl.cert.x509extension] contains "othername:UPN<" } {
                set tmpupn [findstr [ACCESS::session data get session.ssl.cert.x509extension] "othername:UPN<" 14 ">"]
                ACCESS::session data set session.custom.idam.upn $tmpupn
                log local0. "Extracted EDIPI: $tmpupn"
            }
        if { [ACCESS::session data get session.ssl.cert.x509extension] contains "email:" } {
          set tmpemail [findstr [ACCESS::session data get session.ssl.cert.x509extension] "email:" 6 " "]
          regexp {[a-zA-Z.0-9]+@[a-zA-Z.0-9]+\.[a-zA-Z]{2,}} $tmpemail cleanemail
          ACCESS::session data set session.custom.idam.email $cleanemail
          log local0. "Extracted Email Field: $cleanemail"
        }
            if { [ACCESS::session data get session.ssl.cert.subject] contains "CN="} {
             set tmpcn [findstr [ACCESS::session data get session.ssl.cert.subject] "CN=" 3 ,]
             ACCESS::session data set session.custom.idam.tmpcn $tmpcn
             log local0. "Extracted CN: $tmpcn"
            }
            if { [ACCESS::session data get session.ssl.cert.subject] contains "C="} {
             set tmpc [findstr [ACCESS::session data get session.ssl.cert.subject] "C=" 2 ,]
             ACCESS::session data set session.custom.idam.country $tmpc
             log local0. "Extracted Country: $tmpc"
            }
            if { [ACCESS::session data get session.ssl.cert.subject] contains "O="} {
             set tmpo [findstr [ACCESS::session data get session.ssl.cert.subject] "O=" 2 ,]
             ACCESS::session data set session.custom.idam.org $tmpo
             log local0. "Extracted Org: $tmpo"
            }
        #Figure out how to pull validity / expiration dates
        if { [ACCESS::session data get session.ssl.cert.end] ne ""} {
         set expire [ACCESS::session data get session.ssl.cert.end]
         ACCESS::session data set session.custom.idam.expiration $expire
        }
        if { [ACCESS::session data get session.ssl.cert.subject] ne ""} {
        set data [ACCESS::session data get "session.ssl.cert.subject"]
        set commonName [findstr $data "CN=" 3 ","]
        set fullcn "CN=[findstr $data "CN=" 3 "\r"]"
        log local0. "FullCN: $fullcn"
        set cert_list [split $data ","]
        scan $commonName {%[^\.].%[^\.].%[^\.].%[^\.].%[^\.]} last first middle suffix edipinum
        #log local0. "CommonName for Scan: $commonName"
        if { [info exists edipinum] } {
          log local0. "Suffix is $suffix"
          log local0. "EDIPI is $edipinum"
          ACCESS::session data set session.custom.idam.edipinum $edipinum
        } elseif { [info exists suffix] } {
          ACCESS::session data set session.custom.idam.edipinum $suffix
          log local0. "EDIPI is $suffix"
          }
          elseif { [info exists middle] } {
            ACCESS::session data set session.custom.idam.edipinum $middle
            log local0. "EDIPI is $middle"
          }
            ACCESS::session data set session.custom.idam.common $commonName
            ACCESS::session data set session.custom.idam.lastname $last
            ACCESS::session data set session.custom.idam.firstname $first
            ACCESS::session data set session.custom.idam.sam [concat [string range $first 0 0]$last]
            ACCESS::session data set session.custom.idam.dn "CN=$commonName,$ldap_user_dn_suffix"
            ACCESS::session data set session.custom.idam.cn $commonName
            ACCESS::session data set session.custom.idam.fullcn $fullcn

            #log local0. "SAM: [ACCESS::session data get session.custom.idam.sam]"
            #log local0. "Creating SFDC User: $commonName, $last, $first, $tmpemail"
            set log_email [ACCESS::session data get session.custom.idam.email]
            set log_edipi [ACCESS::session data get session.custom.idam.edipinum]
            #log local0. "SFDC Federated User Data: IDPName: $log_email, NameID: $log_edipi"
        }
        }
     }
}


