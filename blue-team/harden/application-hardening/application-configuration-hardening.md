# Application Configuration Hardening

## Check List

* [ ] Compare software configurations against approved security baselines.
* [ ] Disable unnecessary features, services, modules, endpoints, methods, protocols, sample content, default accounts, debug modes, and verbose error messages.
* [ ] Enforce least privilege, secure defaults, strong authentication and authorization, restrictive file permissions, process isolation, network segmentation, and controlled inbound/outbound access.
* [ ] Harden sessions, cookies, security headers, TLS, cryptographic algorithms, CORS, CSRF protection, file uploads, parsers, deserialization, and administrative interfaces.
* [ ] Remove embedded credentials and protect secrets, configuration files, keys, logs, backups, and sensitive environment variables using centralized access-controlled storage.
* [ ] Enable audit logging, integrity monitoring, configuration-drift detection, vulnerability remediation, periodic baseline validation, and controlled change management.

## Cheat Sheet

#### [Apache](https://httpd.apache.org/)

{% hint style="info" %}
Limit Information provided by Apache Web Server by Editing httpd.conf or apache2.conf
{% endhint %}

```bash
ServerTokens Prod
ServerSignature Off
```

{% hint style="info" %}
Disable Directory Listings in Apache configuration or within .htaccess files
{% endhint %}

```bash
Options -Indexes
```

{% hint style="info" %}
Use HTTPS and Redirect HTTP Traffic by adding the following to your virtual host configuration
{% endhint %}

```bash
Redirect permanent "/" "$URL"
```

{% hint style="info" %}
Restrict Access with .htaccess
{% endhint %}

```bash
Require ip $IP
```

{% hint style="info" %}
Secure Sensitive Directories
{% endhint %}

```bash
<Location "$PATH">
  Require host $URL
</Location>
```

{% hint style="info" %}
Limit Request Size in httpd.conf
{% endhint %}

```bash
LimitRequestBody 102400
```

{% hint style="info" %}
Employ Custom .html Error Pages
{% endhint %}

```bash
ErrorDocument 404 $PATH_TO_ERROR_PAGE
```

{% hint style="info" %}
Disable Unnecessary HTTP Methods
{% endhint %}

```bash
Limit PUT DELETE
```

{% hint style="info" %}
Enable Only Necessary HTTP Methods & Disable Other Methods
{% endhint %}

```bash
LimitExcept GET POST OPTIONS
```

{% hint style="info" %}
Disable TRACE Method
{% endhint %}

```bash
TraceEnable Off
```

{% hint style="info" %}
Implement Content Security Policy (CSP) headers through Apache configuration to mitigate XSS risks
{% endhint %}

```bash
Header set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'"
```

{% hint style="info" %}
list active modules
{% endhint %}

```bash
apache2ctl -M
```

{% hint style="info" %}
Disable unused modules
{% endhint %}

```bash
a2dismod status  # Removes /server-status endpoint
a2dismod info    # Removes /server-info endpoint
a2dismod autoindex  # Disables directory listing (alternative to -Indexes)
```

{% hint style="info" %}
Secure SSL/TLS Configuration
{% endhint %}

```bash
<VirtualHost *:443>
    ServerName $DOMAIN
    SSLEngine on
    SSLCertificateFile $CERT_PATH
    SSLCertificateKeyFile $KEY_PATH
    SSLCertificateChainFile $CERT_CHAIN_PATH

    # Only TLS 1.2 and 1.3
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    # Modern cipher suite
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off

    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
</VirtualHost>
```

{% hint style="info" %}
Enable mod\_headers to implement Security Headers
{% endhint %}

```bash
a2enmod headers
systemctl restart apache2
```

{% hint style="info" %}
Implement Security Headers via mod\_headers in VirtualHost or in a global .conf file
{% endhint %}

```bash
<IfModule mod_headers.c>
    Header always set X-Frame-Options 'DENY'
    Header always set X-Content-Type-Options 'nosniff'
    Header always set X-XSS-Protection '1; mode=block'
    Header always set Referrer-Policy 'strict-origin-when-cross-origin'
    Header always set Permissions-Policy 'geolocation=(), microphone=(), camera=()'
    Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; frame-ancestors 'none';"

    # Remove potentially leaky headers
    Header unset X-Powered-By
    Header unset X-AspNet-Version
    Header unset X-AspNetMvc-Version
</IfModule>
```

#### [Nginx](https://nginx.org/)

{% hint style="info" %}
Minimize Information Disclosure
{% endhint %}

```bash
server_tokens off;
```

{% hint style="info" %}
Implement HTTPS with Strong SSL/TLS Configuration
{% endhint %}

```bash
ssl_certificate $CERT_PATH;
ssl_certificate_key $KEY_PATH;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
```

{% hint style="info" %}
Disable Unnecessary HTTP Methods
{% endhint %}

```bash
if ($request_method !~ ^(GET|HEAD|POST)$) {
  return 405;
}
```

{% hint style="info" %}
Limit Rate of Requests
{% endhint %}

```bash
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
```

{% hint style="info" %}
Secure Sensitive Directories and Files
{% endhint %}

```bash
location ~ /(\\.ht|\\.git|\\.svn) {
  deny all;
}
```

{% hint style="info" %}
Employ Access Control
{% endhint %}

```bash
location /admin {
  allow $IP; # Or IP range
  deny all; # Deny all others if using whitelist approach, you can specify IP or IP range
}
```

{% hint style="info" %}
Hide Nginx Version
{% endhint %}

```bash
server_tokens off;
```

{% hint style="info" %}
Implement a Web Application Firewall (WAF)
{% endhint %}

```bash
modsecurity on;
modsecurity_rules_file $MODSECURITY_RULES_PATH;
```

{% hint style="info" %}
Use Secure Connection Headers
{% endhint %}

```bash
add_header X-Frame-Options "SAMEORIGIN" always; # Prevent clickjacking attacks
add_header X-Content-Type-Options "nosniff" always; # Prevent MIME type sniffing
add_header X-XSS-Protection "1; mode=block" always; # Enable XSS protection
add_header Referrer-Policy "strict-origin-when-cross-origin" always; # Referrer policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always; # Content Security Policy (customize based on your needs)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always; # HTTP Strict Transport Security (HTTPS only)
```

{% hint style="info" %}
Disable Server-Side Code Execution on Upload Directories
{% endhint %}

```bash
location /uploads {
  location ~ \.php$ {return 403;}
}
```

{% hint style="info" %}
Content Security Policy (CSP) Implementation
{% endhint %}

```bash
add_header Content-Security-Policy "default-src 'self'; script-src 'self'";
```
