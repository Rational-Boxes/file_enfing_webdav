#define LDAP_DEPRECATED 1

#include "ldap_authenticator.h"
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <cctype>
#include <ldap.h>

namespace webdav {

LDAPAuthenticator::LDAPAuthenticator(
    const std::string& ldap_endpoint,
    const std::string& ldap_domain,
    const std::string& bind_dn,
    const std::string& bind_password,
    const std::string& tenant_base,
    const std::string& user_base)
    : ldap_endpoint_(ldap_endpoint),
      ldap_domain_(ldap_domain),
      bind_dn_(bind_dn),
      bind_password_(bind_password),
      tenant_base_(tenant_base.empty() ? ldap_domain : tenant_base),
      user_base_(user_base.empty() ? ldap_domain : user_base) {
}

LDAPAuthenticator::~LDAPAuthenticator() {
}

UserInfo LDAPAuthenticator::authenticateUser(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(ldap_mutex_);

    LDAP* ld = connectToLDAP();
    if (!ld) {
        std::cerr << "Failed to connect to LDAP server" << std::endl;
        return { "", "", {}, "", false };
    }

    // First, try to bind with the user's credentials
    std::string user_dn;
    LDAPMessage* result = nullptr;

    // Search for the user's DN
    std::string search_filter = "(uid=" + username + ")";
    int ldap_result = ldap_search_s(
        ld,
        user_base_.c_str(),  // Use the configured user base
        LDAP_SCOPE_SUBTREE,
        search_filter.c_str(),
        nullptr,
        false,
        &result
    );

    if (ldap_result != LDAP_SUCCESS) {
        std::cerr << "LDAP search failed: " << ldap_err2string(ldap_result) << std::endl;
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    int count = ldap_count_entries(ld, result);
    if (count != 1) {
        std::cerr << "User not found or multiple entries found" << std::endl;
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        std::cerr << "Failed to get LDAP entry" << std::endl;
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    char* dn = ldap_get_dn(ld, entry);
    if (!dn) {
        std::cerr << "Failed to get DN" << std::endl;
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    user_dn = std::string(dn);
    ldap_memfree(dn);

    // Now try to bind with the user's DN and provided password
    struct berval cred;
    cred.bv_val = const_cast<char*>(password.c_str());
    cred.bv_len = password.length();

    ldap_result = ldap_sasl_bind_s(
        ld,
        user_dn.c_str(),
        LDAP_SASL_SIMPLE,
        &cred,
        nullptr,
        nullptr,
        nullptr
    );

    ldap_msgfree(result);

    if (ldap_result != LDAP_SUCCESS) {
        std::cerr << "User authentication failed: " << ldap_err2string(ldap_result) << std::endl;
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    // Authentication successful, now get user info
    UserInfo user_info = searchUser(ld, username);
    user_info.authenticated = true;

    ldap_unbind_ext_s(ld, nullptr, nullptr);
    return user_info;
}

bool LDAPAuthenticator::authenticateDigest(const std::string& username, const std::string& realm, 
                                          const std::string& nonce, const std::string& uri, 
                                          const std::string& response, const std::string& method) {
    // For digest authentication, we need to retrieve the user's password hash from LDAP
    // This is a simplified implementation - in practice, you'd need to retrieve the HA1 hash
    // from the LDAP directory if it stores it, or compute it from the plain text password
    
    std::lock_guard<std::mutex> lock(ldap_mutex_);
    
    LDAP* ld = connectToLDAP();
    if (!ld) {
        std::cerr << "Failed to connect to LDAP server" << std::endl;
        return false;
    }

    // Search for the user's DN
    std::string search_filter = "(uid=" + username + ")";
    LDAPMessage* result = nullptr;
    int ldap_result = ldap_search_s(
        ld,
        ldap_domain_.c_str(),
        LDAP_SCOPE_SUBTREE,
        search_filter.c_str(),
        nullptr,
        false,
        &result
    );

    if (ldap_result != LDAP_SUCCESS) {
        std::cerr << "LDAP search failed: " << ldap_err2string(ldap_result) << std::endl;
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return false;
    }

    int count = ldap_count_entries(ld, result);
    if (count != 1) {
        std::cerr << "User not found or multiple entries found" << std::endl;
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return false;
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        std::cerr << "Failed to get LDAP entry" << std::endl;
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return false;
    }

    // In a real implementation, we would retrieve the HA1 hash from the LDAP directory
    // For now, we'll just return false as this requires specific LDAP schema setup
    // that stores digest authentication hashes
    
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, nullptr, nullptr);
    
    // Placeholder implementation - would need to retrieve HA1 hash from LDAP
    // and compare with the expected response
    return false;
}

UserInfo LDAPAuthenticator::getUserInfo(const std::string& username) {
    std::lock_guard<std::mutex> lock(ldap_mutex_);
    
    LDAP* ld = connectToLDAP();
    if (!ld) {
        std::cerr << "Failed to connect to LDAP server" << std::endl;
        return { "", "", {}, "", false };
    }

    UserInfo user_info = searchUser(ld, username);
    user_info.authenticated = true; // Assume user is already authenticated

    ldap_unbind_ext_s(ld, nullptr, nullptr);
    return user_info;
}

LDAP* LDAPAuthenticator::connectToLDAP() {
    LDAP* ld = nullptr;
    int version = LDAP_VERSION3;

    int rc = ldap_initialize(&ld, ldap_endpoint_.c_str());
    if (rc != LDAP_SUCCESS) {
        std::cerr << "Failed to initialize LDAP connection: " << ldap_err2string(rc) << std::endl;
        return nullptr;
    }

    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    // Bind with service account
    struct berval cred;
    cred.bv_val = const_cast<char*>(bind_password_.c_str());
    cred.bv_len = bind_password_.length();

    rc = ldap_sasl_bind_s(
        ld,
        bind_dn_.c_str(),
        LDAP_SASL_SIMPLE,
        &cred,
        nullptr,
        nullptr,
        nullptr
    );

    if (rc != LDAP_SUCCESS) {
        std::cerr << "Failed to bind to LDAP server: " << ldap_err2string(rc) << std::endl;
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return nullptr;
    }

    return ld;
}

UserInfo LDAPAuthenticator::searchUser(LDAP* ld, const std::string& username) {
    std::string search_filter = "(uid=" + username + ")";
    LDAPMessage* result = nullptr;

    std::cout << "[DEBUG] Searching for user with base: " << user_base_ << " and filter: " << search_filter << std::endl;

    int ldap_result = ldap_search_s(
        ld,
        user_base_.c_str(),  // Use the configured user base
        LDAP_SCOPE_SUBTREE,
        search_filter.c_str(),
        nullptr,
        false,
        &result
    );

    if (ldap_result != LDAP_SUCCESS) {
        std::cerr << "[ERROR] User search failed: " << ldap_err2string(ldap_result) << std::endl;
        std::cerr << "[ERROR] Search base: " << user_base_ << ", Filter: " << search_filter << std::endl;
        return { "", "", {}, "", false };
    }

    int count = ldap_count_entries(ld, result);
    if (count != 1) {
        std::cerr << "[ERROR] User not found or multiple entries found (count: " << count << ")" << std::endl;
        ldap_msgfree(result);
        return { "", "", {}, "", false };
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        std::cerr << "[ERROR] Failed to get LDAP entry" << std::endl;
        ldap_msgfree(result);
        return { "", "", {}, "", false };
    }

    char* dn = ldap_get_dn(ld, entry);
    if (!dn) {
        std::cerr << "[ERROR] Failed to get DN" << std::endl;
        ldap_msgfree(result);
        return { "", "", {}, "", false };
    }

    UserInfo user_info;
    user_info.dn = std::string(dn);
    user_info.user_id = username;
    user_info.tenant = extractTenantFromUserDN(user_info.dn);

    std::cout << "[DEBUG] Found user: " << user_info.user_id << " with DN: " << user_info.dn << std::endl;
    std::cout << "[DEBUG] Extracting roles for user from groups..." << std::endl;

    // Extract roles from groups the user belongs to
    user_info.roles = extractRolesFromGroups(ld, user_info.dn);
    user_info.authenticated = false; // Will be set by caller

    ldap_memfree(dn);
    ldap_msgfree(result);

    std::cout << "[DEBUG] User roles extracted: " << user_info.roles.size() << " roles" << std::endl;
    for (size_t i = 0; i < user_info.roles.size(); ++i) {
        std::cout << "[DEBUG]   Role " << i+1 << ": " << user_info.roles[i] << std::endl;
    }

    return user_info;
}

std::string LDAPAuthenticator::extractTenantFromUserDN(const std::string& user_dn) {
    // Example: if user DN is "uid=john,ou=users,ou=tenant1,dc=example,dc=com"
    // we want to extract "tenant1" from the ou=tenant1 part
    
    size_t pos = user_dn.find(",ou=");
    if (pos != std::string::npos) {
        pos += 4; // Skip ",ou="
        size_t end_pos = user_dn.find(",", pos);
        if (end_pos != std::string::npos) {
            std::string org_unit = user_dn.substr(pos, end_pos - pos);
            
            // If the org unit contains a hyphen, only take the part before it
            size_t hyphen_pos = org_unit.find("-");
            if (hyphen_pos != std::string::npos) {
                return org_unit.substr(0, hyphen_pos);
            }
            
            return org_unit;
        }
    }
    
    // Default to empty tenant if not found
    return "";
}

std::vector<std::string> LDAPAuthenticator::extractRolesFromGroups(LDAP* ld, const std::string& user_dn) {
    std::vector<std::string> roles;

    // Search for groupOfNames entities the user belongs to
    // Using member attribute to find groups that contain this user
    std::string search_filter = "(&(objectClass=groupOfNames)(member=" + user_dn + "))";
    LDAPMessage* result = nullptr;

    // Use tenant_base_ if configured, otherwise fall back to ldap_domain_
    // For the default tenant, we should look in ou=default under the tenant base
    std::cout << "[DEBUG] Starting group search for user: " << user_dn << std::endl;
    std::cout << "[DEBUG] Tenant base: '" << tenant_base_ << "'" << std::endl;
    std::cout << "[DEBUG] LDAP domain: '" << ldap_domain_ << "'" << std::endl;

    std::string search_base;
    if (!tenant_base_.empty()) {
        // If tenant_base is configured, look for default tenant under that base
        // Check if the tenant_base already includes the tenant OU
        if (tenant_base_.find("ou=default") == 0) {
            // tenant_base already specifies the default tenant
            search_base = tenant_base_;
        } else {
            // Prepend ou=default to the tenant base
            search_base = "ou=default," + tenant_base_;
        }
    } else {
        // Otherwise, construct the full path to default tenant
        search_base = "ou=default,ou=tenants," + ldap_domain_;
    }

    std::cout << "[DEBUG] Using search base: '" << search_base << "'" << std::endl;
    std::cout << "[DEBUG] Using search filter: '" << search_filter << "'" << std::endl;

    std::cout << "[DEBUG] Searching for groups with base: " << search_base << " and filter: " << search_filter << std::endl;

    int ldap_result = ldap_search_s(
        ld,
        search_base.c_str(),  // Use the configured tenant base or fallback to domain
        LDAP_SCOPE_SUBTREE,
        search_filter.c_str(),
        nullptr,
        false,
        &result
    );

    if (ldap_result != LDAP_SUCCESS) {
        std::cerr << "[ERROR] Group search failed: " << ldap_err2string(ldap_result) << std::endl;
        std::cerr << "[ERROR] Search base: " << search_base << ", Filter: " << search_filter << std::endl;
        // If group search fails, assign default 'users' role
        roles.push_back("users");
        return roles;
    }

    std::cout << "[DEBUG] Group search successful, found results" << std::endl;

    // Iterate through all found groups
    int group_count = 0;
    for (LDAPMessage* entry = ldap_first_entry(ld, result); entry != nullptr; entry = ldap_next_entry(ld, entry)) {
        group_count++;
        BerElement* ber = nullptr;
        char* attr = nullptr;

        // Look for cn attribute which typically contains the role name
        for (attr = ldap_first_attribute(ld, entry, &ber); attr != nullptr; attr = ldap_next_attribute(ld, entry, ber)) {
            if (strcmp(attr, "cn") == 0) {  // cn typically contains the group/role name
                berval** vals = ldap_get_values_len(ld, entry, attr);
                if (vals != nullptr) {
                    for (int i = 0; vals[i] != nullptr; i++) {
                        std::string role_name(vals[i]->bv_val);

                        std::cout << "[DEBUG] Found group with role name: " << role_name << std::endl;

                        // Standardize role names to match expected values
                        if (role_name == "users" || role_name == "contributors" || role_name == "administrators" ||
                            role_name == "Users" || role_name == "Contributors" || role_name == "Administrators" ||
                            role_name == "user" || role_name == "contributor" || role_name == "administrator") {
                            // Convert to lowercase for consistency
                            std::transform(role_name.begin(), role_name.end(), role_name.begin(), ::tolower);
                            roles.push_back(role_name);
                            std::cout << "[DEBUG] Assigned role: " << role_name << " to user" << std::endl;
                        } else {
                            std::cout << "[DEBUG] Ignoring unrecognized role: " << role_name << std::endl;
                        }
                    }
                    ldap_value_free_len(vals);
                }
            }
            ldap_memfree(attr);
        }
        if (ber != nullptr) {
            ber_free(ber, 0);
        }
    }

    std::cout << "[DEBUG] Found " << group_count << " group(s) for user " << user_dn << std::endl;

    ldap_msgfree(result);

    // If no specific roles found, assign default 'users' role
    if (roles.empty()) {
        roles.push_back("users");
    }

    return roles;
}

} // namespace webdav