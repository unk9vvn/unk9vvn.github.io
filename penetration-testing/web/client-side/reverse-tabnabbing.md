# Reverse Tabnabbing

## Check List

## Methodology

### Black Box

#### [Reverse Tab-Nabbing](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Tabnabbing#exploit)

{% stepper %}
{% step %}
During testing of user-controlled outbound links (such as Instagram Bio URLs), navigate to a profile and click the external link to observe how the platform opens it. Inspect the generated `<a>` element in the DOM to check whether security attributes like `rel="noopener"` or `rel="noreferrer"` are applied to prevent the child page from accessing `window.opener`
{% endstep %}

{% step %}
Open the external link in a new browser tab and verify whether the child page can still access the opener context
{% endstep %}

{% step %}
Using the browser developer console on the newly opened page, check if `window.opener` is defined. If `window.opener` is accessible despite the presence of `noopener/noreferrer` in the parent page, the link is improperly protected and the parent tab may be exposed to reverse tab-nabbing
{% endstep %}

{% step %}
Create a testing page on an attacker-controlled domain (`attacker.com`) that checks whether the opener object exists and attempts to interact with it. This page can detect if `window.opener` is available and simulate a redirect of the parent tab to demonstrate how reverse tab-nabbing could occur

```html
<!DOCTYPE html>
<html>
<head><title>Reverse Tab-Nabbing Test</title></head>
<body>
<h1 id="msg"></h1>
<script>
    const msg = document.getElementById("msg");
    if (window.opener) {
        msg.textContent = "Opener detected — parent tab is accessible.";
        setTimeout(() => {
            window.opener.location.replace("https://example.com");
        }, 3000);
    } else {
        msg.textContent = "No opener — parent tab is protected.";
    }
</script>
</body>
</html>
```
{% endstep %}

{% step %}
Add the link to the attacker test page into the profile Bio (on Instagram), and view the profile as a real user in various browsers (Chrome, Firefox, etc.). When the user clicks the link while browsing normally, the test page will detect whether `window.opener` is exposed. If the browser allows access to `window.opener`, the test page will demonstrate the vulnerability by redirecting the parent tab. This confirms that reverse tab-nabbing is possible under the tested conditions
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
