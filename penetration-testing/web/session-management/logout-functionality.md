# Logout Functionality

## Check List

## Methodology

### Black Box

#### Logout Bypass

{% stepper %}
{% step %}
Open the browser and go to the login page of the target
{% endstep %}

{% step %}
Enter a valid username/email and password
{% endstep %}

{% step %}
Submit the login form, Successfully access the authenticated dashboard
{% endstep %}

{% step %}
Click the Logout button
{% endstep %}

{% step %}
Confirm you are redirected to the login page or a "Logged out" message appears
{% endstep %}

{% step %}
Immediately after logout, press the Back button (or use keyboard shortcut `Alt + ←`)
{% endstep %}

{% step %}
Observe if the previous authenticated page reloads and you still have full access
{% endstep %}

{% step %}
Navigate freely inside the dashboard
{% endstep %}

{% step %}
Perform a privileged action (change settings, view private data) → If successful → Logout bypass confirmed
{% endstep %}
{% endstepper %}

***

#### **Failure to Invalidate Session on Logout**

{% stepper %}
{% step %}
Login to the application using Chrome Browser and browse the application
{% endstep %}

{% step %}
Use `“Edit this Cookie”` plugin in Chrome and copy all the cookies present
{% endstep %}

{% step %}
Now Logout from the application and Clear the cookies from browser
{% endstep %}

{% step %}
Use “Edit this Cookie” plugin and paste all the cookies that copied earlier
{% endstep %}

{% step %}
Click on Okay and refresh the page , can see the application is getting logged in
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
