from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry


class NXCModule:
    """
    Module by @RyanVoit
    
    Based on scomhunter tool's find functionality
    Enumerates SCOM (System Center Operations Manager) infrastructure via LDAP
    """

    name = "scom-hunter"
    description = "Enumerate SCOM infrastructure (Management Servers and SDK Service Accounts)"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        No options required.
        
        This module will automatically search for:
        - SCOM Management Servers (computers with MSOMHSvc SPN)
        - SCOM SDK Service Accounts (users with MSOMSdkSvc SPN)
        
        Example:
        nxc ldap $DC-IP -u Username -p Password -M scom-hunter
        """
        pass

    def on_login(self, context, connection):
        """Search for SCOM infrastructure components"""
        
        context.log.display("Starting SCOM infrastructure enumeration...")
        
        # Search for SCOM Management Servers
        self.find_management_servers(context, connection)
        
        # Search for SCOM SDK Service Accounts
        self.find_sdk_users(context, connection)

    def find_management_servers(self, context, connection):
        """Find SCOM Management Servers by searching for MSOMHSvc ServicePrincipalName"""
        
        context.log.display("Searching for SCOM Management Servers...")
        search_filter = "(serviceprincipalname=MSOMHSvc/*)"
        attributes = ["dNSHostName", "servicePrincipalName", "operatingSystem"]
        
        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldap_connection.search(
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=0
            )
        except LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, processing received data")
                resp = e.getAnswers()
            else:
                context.log.fail(f"LDAP search error: {e}")
                nxc_logger.debug(e)
                return False
        except Exception as e:
            context.log.fail(f"Error searching for Management Servers: {e}")
            return False

        # Process results
        servers = []
        context.log.debug(f"Total no. of Management Server records returned: {len(resp)}")
        
        for item in resp:
            if isinstance(item, SearchResultEntry) is not True:
                continue
            
            dns_host_name = ""
            spns = []
            operating_system = ""
            
            try:
                for attribute in item["attributes"]:
                    attr_type = str(attribute["type"])
                    if attr_type == "dNSHostName":
                        dns_host_name = str(attribute["vals"][0])
                    elif attr_type == "servicePrincipalName":
                        spns = [str(spn) for spn in attribute["vals"]]
                    elif attr_type == "operatingSystem":
                        operating_system = str(attribute["vals"][0])
                
                if dns_host_name:
                    # Check if server has both MSOMHSvc and MSOMSdkSvc (potentially vulnerable)
                    has_hsvc = any("MSOMHSvc" in spn for spn in spns)
                    has_sdksvc = any("MSOMSdkSvc" in spn for spn in spns)
                    is_vulnerable = has_hsvc and has_sdksvc
                    
                    servers.append({
                        "hostname": dns_host_name,
                        "spns": spns,
                        "os": operating_system,
                        "vulnerable": is_vulnerable
                    })
            except Exception as e:
                context.log.debug(f"Exception processing item: {e}")
                continue

        # Display results
        if len(servers) > 0:
            context.log.success(f"Found {len(servers)} SCOM Management Server(s):")
            for server in servers:
                vuln_marker = " [VULNERABLE - Has both MSOMHSvc and MSOMSdkSvc SPNs]" if server["vulnerable"] else ""
                context.log.highlight(f"  {server['hostname']}{vuln_marker}")
                if server["os"]:
                    context.log.info(f"    OS: {server['os']}")
                context.log.info(f"    SPNs:")
                for spn in server["spns"]:
                    context.log.info(f"      - {spn}")
        else:
            context.log.fail("No SCOM Management Servers found. SCOM may not be in use.")

    def find_sdk_users(self, context, connection):
        """Find SCOM Data Access Service Accounts (SDK users)"""
        
        context.log.display("Searching for SCOM SDK Service Accounts...")
        search_filter = "(&(serviceprincipalname=MSOMSdkSvc/*)(samaccounttype=805306368)(!(samaccounttype=805306370)))"
        attributes = ["userPrincipalName", "sAMAccountName", "servicePrincipalName", "description", "pwdLastSet"]
        
        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldap_connection.search(
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=0
            )
        except LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, processing received data")
                resp = e.getAnswers()
            else:
                context.log.fail(f"LDAP search error: {e}")
                nxc_logger.debug(e)
                return False
        except Exception as e:
            context.log.fail(f"Error searching for SDK users: {e}")
            return False

        # Process results
        users = []
        context.log.debug(f"Total no. of SDK user records returned: {len(resp)}")
        
        for item in resp:
            if isinstance(item, SearchResultEntry) is not True:
                continue
            
            user_principal_name = ""
            sam_account_name = ""
            spns = []
            description = ""
            pwd_last_set = ""
            
            try:
                for attribute in item["attributes"]:
                    attr_type = str(attribute["type"])
                    if attr_type == "userPrincipalName":
                        user_principal_name = str(attribute["vals"][0])
                    elif attr_type == "sAMAccountName":
                        sam_account_name = str(attribute["vals"][0])
                    elif attr_type == "servicePrincipalName":
                        spns = [str(spn) for spn in attribute["vals"]]
                    elif attr_type == "description":
                        description = str(attribute["vals"][0])
                    elif attr_type == "pwdLastSet":
                        pwd_last_set = str(attribute["vals"][0])
                
                if user_principal_name or sam_account_name:
                    users.append({
                        "upn": user_principal_name,
                        "sam": sam_account_name,
                        "spns": spns,
                        "description": description,
                        "pwd_last_set": pwd_last_set
                    })
            except Exception as e:
                context.log.debug(f"Exception processing item: {e}")
                continue

        # Display results
        if len(users) > 0:
            context.log.success(f"Found {len(users)} SCOM SDK Service Account(s):")
            for user in users:
                username = user["upn"] if user["upn"] else user["sam"]
                context.log.highlight(f"  {username}")
                if user["description"]:
                    context.log.info(f"    Description: {user['description']}")
                if user["pwd_last_set"]:
                    context.log.info(f"    Password Last Set: {user['pwd_last_set']}")
                context.log.info(f"    SPNs:")
                for spn in user["spns"]:
                    context.log.info(f"      - {spn}")
        else:
            context.log.fail("No SCOM SDK Service Accounts found.")
