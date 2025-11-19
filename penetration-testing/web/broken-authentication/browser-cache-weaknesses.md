# Browser Cache Weaknesses

## Check List

## Methodology

### Black Box

#### History Exposure

{% stepper %}
{% step %}
Go to any page that displays sensitive data like Login Success Page
{% endstep %}

{% step %}
Enter or trigger sensitive information, Enter password And Submit or Load the Page
{% endstep %}

{% step %}
Click Logout, Confirm redirected to login page
{% endstep %}

{% step %}
If the previous page with sensitive data reloads, History Exposure Confirmed
{% endstep %}
{% endstepper %}

***

#### Browser Cache Manually

{% stepper %}
{% step %}
If you are using Chrome browser, go to `chrome://cache` in the URL (For FireFox Browser `about:cache`)
{% endstep %}

{% step %}
Search for target domain
{% endstep %}

{% step %}
If sensitive page is cached, Cache Exposure Confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
