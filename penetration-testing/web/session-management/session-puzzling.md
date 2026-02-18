# Session Puzzling

## Check List

## Methodology

### Black Box

#### Bypassing Authentication

{% stepper %}
{% step %}
Navigate to the target application in a browser
{% endstep %}

{% step %}
Observe that a new HTTP session is created and a session ID is assigned to your browser
{% endstep %}

{% step %}
Go to the **Forgot Password** page.
{% endstep %}

{% step %}
Enter a **valid username** (one that exists in the system).
{% endstep %}

{% step %}
Submit the reset password request.
{% endstep %}

{% step %}
Intercept the request/response using a proxy tool (e.g., Burp Suite).
{% endstep %}

{% step %}
Observe that upon submitting a valid username: A session variable (e.g., `userid`) is created on the server, The session variable stores the supplied username, No authentication has occurred yet
{% endstep %}

{% step %}
Without completing the password reset process and without logging in, manually navigate to a post-authentication page, such as: `/home` , `/dashboard` , `/edit-profile`
{% endstep %}

{% step %}
Send the request while keeping the same session cookie
{% endstep %}

{% step %}
Observe that the application allows access to the protected page
{% endstep %}

{% step %}
Confirm that: The application uses the session variable (`userid`) to fetch user-specific data and There is no additional session variable (`authenticated = true`) being validated, Authentication status is not explicitly checked before granting access
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
