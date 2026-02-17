# Weaker Authentication in Alternative Channel

## Check List

## Methodology

### Black Box

#### SSO Misconfiguration

{% stepper %}
{% step %}
Create a legal organization with SSO enabled and verify successful user login (take a baseline)
{% endstep %}

{% step %}
Extract and record the exact entityId (or `issuer/client_id`) value
{% endstep %}

{% step %}
Create a second test organization and record the same value with a minor invisible change (a trailing space or a case change)
{% endstep %}

{% step %}
Set up a separate key/config for the second organization so that it is completely independent
{% endstep %}

{% step %}
Wait for the settings to propagate to the system
{% endstep %}

{% step %}
Log in with the main organization user via SSO
{% endstep %}

{% step %}
Check that authentication at the IdP is successful, but which organization is the user provisioned to
{% endstep %}

{% step %}
If the user is deleted or is a new user, rerun the login test and check the assignment behavior
{% endstep %}

{% step %}
If the user is transferred to the wrong organization or a global error occurs, a mismatch between the Authentication and Provisioning phases is confirmed\\
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
