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

#### **Cache Deception**

{% stepper %}
{% step %}
Log in to the target site and complete the authentication process using
{% endstep %}

{% step %}
Go to the final paths that return sensitive information, such as `/profile`, `/dashboard`, `/my-account`, `/settings`, `/username`, and then capture the request using the Burp Suite tool.
{% endstep %}

{% step %}
When you receive a request for a sensitive path that captures information using the Burp suite tool, add an extension to the end of this path, like this

```hurl
https://dashboard.target.com/my-profile/username/.css
```
{% endstep %}

{% step %}
Check if the HTTP response status is 200 and the response body contains `dynamic/user`-specific content your username, email, profile data, instead of a real CSS file
{% endstep %}

{% step %}
If caching headers are present, open the same URL (`/my-profile/username/.css`) in a private/incognito window or different browser (logged out) and confirm the response still returns your private profile data
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
