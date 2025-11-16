# CSS Injection

## Check List

## Methodology

### Black Box

#### Country Parameter

{% stepper %}
{% step %}
Log into the target site and intercept requests using the Bupr Suite tool
{% endstep %}

{% step %}
Then examine the requests and look for the `country` parameter, as shown below

```url
https://example.com/search?q=a&country=BR
```
{% endstep %}

{% step %}
In the request, modify the country parameter to a random value and observe its reflection in a style attribute like this

```html
<div class="language" style="background-image: url(/BR.svg)"><div>
```
{% endstep %}

{% step %}
If the parameter value was inside a `(..)` we can escape using the `;` character and write a new style and send the following malicious request

```css
https://example.com/search?q=a&country=BR'); width: 9999px; height: 9999px; background: red; //
```
{% endstep %}

{% step %}
And if the page changes, it is confirmed to be vulnerable and displayed in the html as follows

```html
<div class="language" style="background-image: url(/BR.svg'); width: 9999px; height: 9999px; background: red; //)"><div>
```
{% endstep %}
{% endstepper %}

***

#### Base CSS injection

{% stepper %}
{% step %}
Access the target application
{% endstep %}

{% step %}
Navigate to the target page by clicking the relevant button
{% endstep %}

{% step %}
Observe the `HTTP GET` for `/Home/TargetPage`, and inspect the rendered form where the user can change “Color” and “Tag” of a text in that page
{% endstep %}

{% step %}
Submit the form with benign inputs `(Color = “green”, Tag = “h3”`) and inspect the HTTP POST to `/Home/TargetPage`. Confirm that the submitted values are reflected in the response HTML
{% endstep %}

{% step %}
Test for injection by providing a payload like Test for injection by providing a payload like `"><h1>CSSInjection` in the Color and Tag fields. Observe that the Color field is used without validation, whereas Tag input is validated
{% endstep %}

{% step %}
Refine the payload to something like `\" onclick=prompt(8)>` in the Color field to verify reflective XSS within the CSS context or style attribute
{% endstep %}

{% step %}
Exploit the CSS injection, inject attacker‑controlled `CSS` via the `Color` or `style` field and observe its effect on page rendering (`overriding styles`, `altering visual appearance`)
{% endstep %}
{% endstepper %}

***

#### Potential XSS

{% stepper %}
{% step %}
Identify the target resource and confirm that this URL accepts user-controlled input that could potentially lead to CSS injection. The test could be like this

```url
https://example.com/landings/libs/alert/alerts/exitpopup74/exit-popup.php?root=https://+YOUR SERVER+/&lang=en
```
{% endstep %}

{% step %}
On the attacker’s server, create the exit-popup.css file and insert the following code to test the CSS injection

```html
div {
 background-image: url("https://media.giphy.com/media/SggILpMXO7Xt6/giphy.gif");
 background-color: #cccccc;
}
```
{% endstep %}

{% step %}
Observe whether custom CSS is applied or reflected back — check for injected styles altering page rendering
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
