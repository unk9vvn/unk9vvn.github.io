# WebSockets

## Check List

## Methodology

### [Black Box](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets#web-sockets)

#### Hijacking Private Data Leak

{% stepper %}
{% step %}
Log into sites that use file summarization or upload processes or artificial intelligence using websocket requests
{% endstep %}

{% step %}
Search for and identify WebSocket endpoints in Burp Suite
{% endstep %}

{% step %}
Upload a private file, start AI summary, send a message, etc
{% endstep %}

{% step %}
Keep the WebSocket connection open
{% endstep %}

{% step %}
Filter by WS, right-click the upgrade request, Copy, Copy as cURL like

```http
GET /ai/wsio/?EIO=4&transport=websocket HTTP/2
Host: www.target.com
Cookie: session=abc123...
```
{% endstep %}

{% step %}
Paste into Burp Repeater, WebSocket tab
{% endstep %}

{% step %}
Create a new WebSocket connection using the same cookies (from your logged-in session)
{% endstep %}

{% step %}
Just wait, do not upload anything from this session
{% endstep %}

{% step %}
Trigger AI summary, chat message, or any real-time action
{% endstep %}

{% step %}
Go back to your Burp WebSocket, If you see messages like

```json
{
  "contentItem": {
    "id": 987654,
    "content": "This is another user's private document...",
    "summary": "AI summary of secret file...",
    "isPublic": false
  }
}
```
{% endstep %}

{% step %}
WebSocket Hijacking, Private Data Leak CONFIRMED
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
