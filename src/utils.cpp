#include "utils.h"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace webdav {

std::vector<std::string> splitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    
    size_t end = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(start, end - start + 1);
}

std::string urlDecode(const std::string& encoded) {
    std::string decoded;
    for (size_t i = 0; i < encoded.length(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.length()) {
            std::string hex = encoded.substr(i + 1, 2);
            char ch = static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
            decoded += ch;
            i += 2; // Skip the next two characters
        } else if (encoded[i] == '+') {
            decoded += ' ';
        } else {
            decoded += encoded[i];
        }
    }
    return decoded;
}

std::string urlEncode(const std::string& decoded) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : decoded) {
        // Keep alphanumeric and other accepted characters intact
        if (std::isalnum(static_cast<unsigned char>(c)) ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
}

std::string generateDigestHash(const std::string& username, const std::string& realm, const std::string& password) {
    std::string a1 = username + ":" + realm + ":" + password;
    
    Poco::MD5Engine md5;
    md5.update(a1);
    Poco::DigestEngine::Digest digest = md5.digest();
    
    std::string result;
    for (auto byte : digest) {
        result += Poco::NumberFormatter::formatHex(byte, 2);
    }
    
    return result;
}

std::string calculateHA1(const std::string& username, const std::string& realm, const std::string& password) {
    return generateDigestHash(username, realm, password);
}

std::string calculateHA2(const std::string& method, const std::string& uri) {
    std::string a2 = method + ":" + uri;
    
    Poco::MD5Engine md5;
    md5.update(a2);
    Poco::DigestEngine::Digest digest = md5.digest();
    
    std::string result;
    for (auto byte : digest) {
        result += Poco::NumberFormatter::formatHex(byte, 2);
    }
    
    return result;
}

std::string calculateDigestResponse(const std::string& ha1, const std::string& nonce, 
                                  const std::string& nc, const std::string& cnonce, 
                                  const std::string& qop, const std::string& ha2) {
    std::string a3 = ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2;
    
    Poco::MD5Engine md5;
    md5.update(a3);
    Poco::DigestEngine::Digest digest = md5.digest();
    
    std::string result;
    for (auto byte : digest) {
        result += Poco::NumberFormatter::formatHex(byte, 2);
    }
    
    return result;
}

std::string extractTenantFromHostname(const std::string& hostname) {
    // Example: tenant1.example.com -> tenant1
    // Example: tenant-dev.example.com -> tenant (before hyphen)
    // Example: www.example.com -> "" (www excluded)
    
    size_t first_dot = hostname.find('.');
    if (first_dot == std::string::npos) {
        return "";
    }
    
    std::string subdomain = hostname.substr(0, first_dot);
    
    // Exclude www
    if (subdomain == "www") {
        return "";
    }
    
    // If subdomain contains a hyphen, only take the part before it
    size_t hyphen_pos = subdomain.find('-');
    if (hyphen_pos != std::string::npos) {
        return subdomain.substr(0, hyphen_pos);
    }
    
    return subdomain;
}

std::string getEnvOrDefault(const std::string& env_var, const std::string& default_val) {
    std::string val = Poco::Environment::get(env_var, "");
    if (val.empty()) {
        return default_val;
    }
    return val;
}

std::string getErrorMessage(int error_code) {
    // This is a simplified implementation
    // In a real implementation, you would map error codes to meaningful messages
    switch (error_code) {
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 412: return "Precondition Failed";
        case 500: return "Internal Server Error";
        default: return "Unknown Error";
    }
}

} // namespace webdav