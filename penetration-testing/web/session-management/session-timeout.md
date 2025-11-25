# Session Timeout

## Check List

## Methodology

### Black Box

#### Reusing Session IDs

{% stepper %}
{% step %}
Navigate to `https://example.com/` and log into the AWS Management Console using AWS SSO
{% endstep %}

{% step %}
Keep the session idle until the configured session-timeout period is reached and you are automatically logged out of the AWS Management Console
{% endstep %}

{% step %}
After timeout, directly visit the AWS Access Portal URL (`https://example.com/awsapps/portal`) without performing any new authentication
{% endstep %}

{% step %}
Observe that the portal still grants access and allows re-login into AWS services without requiring a fresh SSO authentication, indicating improper session invalidation
{% endstep %}
{% endstepper %}

***

#### Insufficient Session Expiration

{% stepper %}
{% step %}
Open Browser A (Brave) and Browser B (Firefox)
{% endstep %}

{% step %}
Log into the same user account on both browsers using valid credentials
{% endstep %}

{% step %}
In Browser A, navigate to Account Settings → Change Password
{% endstep %}

{% step %}
Update the password to a new value and confirm the successful password change
{% endstep %}

{% step %}
Switch to Browser B and refresh any authenticated page
{% endstep %}

{% step %}
Observe that the session remains active and no re-authentication is required
{% endstep %}
{% endstepper %}

***

#### Password Change

{% stepper %}
{% step %}
Observe session timeout behavior and identify client-side session-clear requests (`/clearSession`)
{% endstep %}

{% step %}
Intercept outgoing requests with a proxy (Burp) and confirm `/clearSession` is sent periodically
{% endstep %}

{% step %}
Create a match-and-replace rule in the proxy to `block/modify` `/clearSession` so it no longer clears the session
{% endstep %}

{% step %}
Verify the session remains active and automated tests can run uninterrupted
{% endstep %}

{% step %}
Inspect logout flow; identify all endpoints called (`/clearSession`, `/authservice/logout`)
{% endstep %}

{% step %}
Confirm whether logout actually invalidates server-side sessions&#x20;
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
