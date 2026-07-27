//! Burp's shipped issue catalog, transcribed. **Generated — do not edit by hand.**
//!
//! Source: `resources/KnowledgeBase/Issues/*.json` from the Burp Suite 2026.7.1 jar,
//! extracted to `/root/burp-re/out/scanner_spec/issues/` by the teardown. Regenerate with
//! `python3 crates/scanner/tools/gen_catalog.py crates/scanner/src/catalog_data.rs`.
//!
//! 183 definitions; 169 carry a remediation (14 are null in
//! the source and stay `None`); 227 references; 433 vulnerability classifications.
//! There is no CVSS data anywhere in the shipped catalog, so no CVSS field exists here.
//!
//! `type_index` is the ID encoded in the filename, which is unique across all 183 files.
//! `declared_type_index` is the `typeIndex` field inside the JSON body; it disagrees in
//! 2 of 183 cases, where the stale value duplicates another issue's ID. Both are
//! kept verbatim rather than reconciled — see `catalog::tests`.
//!
//! Sorted by `type_index` so [`crate::catalog::by_type_index`] can binary-search it.

use crate::catalog::{Classification, IssueDefinition, Reference};
use burpsy_core::Severity;

pub(crate) static ISSUES: &[IssueDefinition] = &[
    IssueDefinition {
        type_index: 1048832,
        declared_type_index: 1048832,
        name: r#"OS command injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Operating system command injection vulnerabilities arise when an application incorporates user-controllable data into a command that is processed by a shell command interpreter. If the user data is not strictly validated, an attacker can use shell metacharacters to modify the command that is executed, and inject arbitrary further commands that will be executed by the server.</p>
<p>OS command injection vulnerabilities are usually very serious and may lead to compromise of the server hosting the application, or of the application's own data and functionality. It may also be possible to use the server as a platform for attacks against other systems. The exact potential for exploitation depends upon the security context in which the command is executed, and the privileges that this context has regarding sensitive resources on the server.</p>"#,
        remediation: Some(r#"<p>If possible, applications should avoid incorporating user-controllable data into operating system commands. In almost every situation, there are safer alternative methods of performing server-level tasks, which cannot be manipulated to perform additional commands than the one intended.</p>
<p>If it is considered unavoidable to incorporate user-supplied data into operating system commands, the following two layers of defense should be used to prevent attacks: </p>
<ul>
  <li>The user data should be strictly validated. Ideally, a whitelist of specific accepted values should be used. Otherwise, only short alphanumeric strings should be accepted. Input containing any other data, including any conceivable shell metacharacter or whitespace, should be rejected.</li>
  <li>The application should use command APIs that launch a specific process via its name and command-line parameters, rather than passing a command string to a shell interpreter that supports command chaining and redirection. For example, the Java API Runtime.exec and the ASP.NET API Process.Start do not support shell metacharacters. This defense can mitigate the impact of an attack even in the event that an attacker circumvents the input validation defenses.</li>
</ul>"#),
        references: &[
            Reference { title: r#"Web Security Academy: OS command injection"#, url: r#"https://portswigger.net/web-security/os-command-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/77.html"# },
            Classification { title: r#"CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/78.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-248: Command Injection"#, url: r#"https://capec.mitre.org/data/definitions/248.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1049088,
        declared_type_index: 1049088,
        name: r#"SQL injection"#,
        typical_severity: Severity::High,
        description: r#"<p>SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.</p>
<p>A wide range of damaging attacks can often be delivered via SQL injection, including reading or modifying critical application data, interfering with application logic, escalating privileges within the database and taking control of the database server. </p>"#,
        remediation: Some(r#"<p>The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. You should review the documentation for your database and application platform to determine the appropriate APIs which you can use to perform parameterized queries. It is strongly recommended that you parameterize <i>every</i> variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.</p>
<p>You should be aware that some commonly employed and recommended mitigations for SQL injection vulnerabilities are not always effective: </p>
<ul>
  <li>One common defense is to double up any single quotation marks appearing within user input before incorporating that input into a SQL query. This defense is designed to prevent malformed data from terminating the string into which it is inserted. However, if the data being incorporated into queries is numeric, then the defense may fail, because numeric data may not be encapsulated within quotes, in which case only a space is required to break out of the data context and interfere with the query. Further, in second-order SQL injection attacks, data that has been safely escaped when initially inserted into the database is subsequently read from the database and then passed back to it again. Quotation marks that have been doubled up initially will return to their original form when the data is reused, allowing the defense to be bypassed.</li>
  <li>Another often cited defense is to use stored procedures for database access. While stored procedures can provide security benefits, they are not guaranteed to prevent SQL injection attacks. The same kinds of vulnerabilities that arise within standard dynamic SQL queries can arise if any SQL is dynamically constructed within stored procedures. Further, even if the procedure is sound, SQL injection can arise if the procedure is invoked in an unsafe manner using user-controllable data.</li>
</ul>"#),
        references: &[
            Reference { title: r#"Web Security Academy: SQL injection"#, url: r#"https://portswigger.net/web-security/sql-injection"# },
            Reference { title: r#"Using Burp to Test for Injection Flaws"#, url: r#"https://support.portswigger.net/customer/portal/articles/1965677-using-burp-to-test-for-injection-flaws"# },
            Reference { title: r#"Web Security Academy: SQL Injection Cheat Sheet"#, url: r#"https://portswigger.net/web-security/sql-injection/cheat-sheet"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/89.html"# },
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-66: SQL Injection"#, url: r#"https://capec.mitre.org/data/definitions/66.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1049104,
        declared_type_index: 1049104,
        name: r#"SQL injection (second order)"#,
        typical_severity: Severity::High,
        description: r#"<p>SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.</p>
<p>A wide range of damaging attacks can often be delivered via SQL injection, including reading or modifying critical application data, interfering with application logic, escalating privileges within the database and taking control of the database server. </p>

<p>Second-order SQL injection arises when user-supplied data is stored by the application and later incorporated into SQL queries in an unsafe way. To detect the vulnerability, it is normally necessary to submit suitable data in one location, and then use some other application function that processes the data in an unsafe way.</p>"#,
        remediation: Some(r#"<p>The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. You should review the documentation for your database and application platform to determine the appropriate APIs which you can use to perform parameterized queries. It is strongly recommended that you parameterize <i>every</i> variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.</p>
<p>You should be aware that some commonly employed and recommended mitigations for SQL injection vulnerabilities are not always effective: </p>
<ul>
  <li>One common defense is to double up any single quotation marks appearing within user input before incorporating that input into a SQL query. This defense is designed to prevent malformed data from terminating the string into which it is inserted. However, if the data being incorporated into queries is numeric, then the defense may fail, because numeric data may not be encapsulated within quotes, in which case only a space is required to break out of the data context and interfere with the query. Further, in second-order SQL injection attacks, data that has been safely escaped when initially inserted into the database is subsequently read from the database and then passed back to it again. Quotation marks that have been doubled up initially will return to their original form when the data is reused, allowing the defense to be bypassed.</li>
  <li>Another often cited defense is to use stored procedures for database access. While stored procedures can provide security benefits, they are not guaranteed to prevent SQL injection attacks. The same kinds of vulnerabilities that arise within standard dynamic SQL queries can arise if any SQL is dynamically constructed within stored procedures. Further, even if the procedure is sound, SQL injection can arise if the procedure is invoked in an unsafe manner using user-controllable data.</li>
</ul>"#),
        references: &[
            Reference { title: r#"Web Security Academy: SQL injection"#, url: r#"https://portswigger.net/web-security/sql-injection"# },
            Reference { title: r#"Using Burp to Test for Injection Flaws"#, url: r#"https://support.portswigger.net/customer/portal/articles/1965677-using-burp-to-test-for-injection-flaws"# },
            Reference { title: r#"Web Security Academy: SQL Injection Cheat Sheet"#, url: r#"https://portswigger.net/web-security/sql-injection/cheat-sheet"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/89.html"# },
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-66: SQL Injection"#, url: r#"https://capec.mitre.org/data/definitions/66.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1049216,
        declared_type_index: 1049216,
        name: r#"ASP.NET tracing enabled"#,
        typical_severity: Severity::High,
        description: r#"<p>ASP.NET tracing is a debugging feature that is designed for use during development to help troubleshoot problems. It discloses sensitive information to users, and if enabled in production contexts may present a serious security threat.</p>
<p>Application-level tracing enables any user to retrieve full details about recent requests to the application, including those of other users. This information typically includes session tokens and request parameters, which may enable an attacker to compromise other users and even take control of the entire application.</p>
<p>Page-level tracing returns the same information, but relating only to the current request. This may still contain sensitive data in session and server variables that would be of use to an attacker.</p>"#,
        remediation: Some(r#"<p>To disable tracing, open the Web.config file for the application, and find the &lt;trace&gt; element within the &lt;system.web&gt; section. Either set the enabled attribute to "false" (to disable tracing) or set the localOnly attribute to "true" (to enable tracing only on the server itself).</p>
<p>Note that even with tracing disabled in this way, it is possible for individual pages to turn on page-level tracing either within the Page directive of the ASP.NET page, or programmatically through application code. If you observe tracing output only on some application pages, you should review the page source and the code behind, to find the reason why tracing is occurring.</p>
<p>It is strongly recommended that you refer to your platform's documentation relating to this issue, and do not rely solely on the above remediation.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-10: ASP.NET Environment Issues
"#, url: r#"https://cwe.mitre.org/data/definitions/10.html"# },
            Classification { title: r#"CWE-11: ASP.NET Misconfiguration: Creating Debug Binary"#, url: r#"https://cwe.mitre.org/data/definitions/11.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1049344,
        declared_type_index: 1049344,
        name: r#"File path traversal"#,
        typical_severity: Severity::High,
        description: r#"<p>File path traversal vulnerabilities arise when user-controllable data is used within a filesystem operation in an unsafe manner. Typically, a user-supplied filename is appended to a directory prefix in order to read or write the contents of a file. If vulnerable, an attacker can supply path traversal sequences (using dot-dot-slash characters) to break out of the intended directory and read or write files elsewhere on the filesystem.</p>
<p>This is typically a very serious vulnerability, enabling an attacker to access sensitive files containing configuration data, passwords, database records, log data, source code, and program scripts and binaries. </p>"#,
        remediation: Some(r#"<p>Ideally, application functionality should be designed in such a way that user-controllable data does not need to be passed to filesystem operations. This can normally be achieved by referencing known files via an index number rather than their name, and using application-generated filenames to save user-supplied file content.</p>
<p>If it is considered unavoidable to pass user-controllable data to a filesystem operation, three layers of defense can be employed to prevent path traversal attacks: </p>
<ul><li>User-controllable data should be strictly validated before being passed to any filesystem operation. In particular, input containing dot-dot sequences should be blocked.</li><li>After validating user input, the application can use a suitable filesystem API to verify that the file to be accessed is actually located within the base directory used by the application. In Java, this can be achieved by instantiating a java.io.File object using the user-supplied filename and then calling the getCanonicalPath method on this object. If the string returned by this method does not begin with the name of the start directory, then the user has somehow bypassed the application's input filters, and the request should be rejected. In ASP.NET, the same check can be performed by passing the user-supplied filename to the System.Io.Path.GetFullPath method and checking the returned string in the same way as described for Java.</li><li>The directory used to store files that are accessed using user-controllable data can be located on a separate logical volume to other sensitive application and operating system files, so that these cannot be reached via path traversal attacks. In Unix-based systems, this can be achieved using a chrooted filesystem; on Windows, this can be achieved by mounting the base directory as a new logical drive and using the associated drive letter to access its contents.</li></ul>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Directory traversal"#, url: r#"https://portswigger.net/web-security/file-path-traversal"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"#, url: r#"https://cwe.mitre.org/data/definitions/22.html"# },
            Classification { title: r#"CWE-23: Relative Path Traversal"#, url: r#"https://cwe.mitre.org/data/definitions/23.html"# },
            Classification { title: r#"CWE-35: Path Traversal: '.../...//'"#, url: r#"https://cwe.mitre.org/data/definitions/35.html"# },
            Classification { title: r#"CWE-36: Absolute Path Traversal"#, url: r#"https://cwe.mitre.org/data/definitions/36.html"# },
            Classification { title: r#"CAPEC-126: Path Traversal"#, url: r#"https://capec.mitre.org/data/definitions/126.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1049600,
        declared_type_index: 1049600,
        name: r#"XML external entity injection"#,
        typical_severity: Severity::High,
        description: r#"<p>XML external entity (XXE) injection vulnerabilities arise when applications process user-supplied XML documents without disabling references to external resources. XML parsers typically support external references by default, even though they are rarely required by applications during normal usage.</p>
<p>External entities can reference files on the parser's filesystem; exploiting this feature may allow retrieval of arbitrary files, or denial of service by causing the server to read from a file such as /dev/random.</p>
<p>External entities can often also reference network resources via the HTTP protocol handler. The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy.
  By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. 
  This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. 
  Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers.
</p>"#,
        remediation: Some(r#"<p>Parsers that are used to process XML from untrusted sources should be configured to disable processing of all external resources. This is usually possible, and will prevent a number of related attacks.&nbsp;You should consult the documentation for your XML parsing library to determine how to achieve this.</p>

<p>XML external entity injection makes use of the DOCTYPE tag to define the injected entity. It may also be possible to disable the DOCTYPE tag or use input validation to block input containing it.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: XXE injection"#, url: r#"https://portswigger.net/web-security/xxe"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-611: Improper Restriction of XML External Entity Reference ('XXE')"#, url: r#"https://cwe.mitre.org/data/definitions/611.html"# },
            Classification { title: r#"CAPEC-228: DTD Injection"#, url: r#"https://capec.mitre.org/data/definitions/228.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1049856,
        declared_type_index: 1049856,
        name: r#"LDAP injection"#,
        typical_severity: Severity::High,
        description: r#"<p>LDAP injection arises when user-controllable data is copied in an unsafe way into an LDAP query that is performed by the application. If an attacker can inject LDAP metacharacters into the query, then they can interfere with the query's logic. Depending on the function for which the query is used, the attacker may be able to retrieve sensitive data to which they are not authorized, or subvert the application's logic to perform some unauthorized action.</p>
<p>Note that automated difference-based tests for LDAP injection flaws can often be unreliable and are prone to false positive results. Scanner results should be manually reviewed to confirm whether a vulnerability is actually present. </p>"#,
        remediation: Some(r#"<p>If possible, applications should avoid copying user-controllable data into LDAP queries. If this is unavoidable, then the data should be strictly validated to prevent LDAP injection attacks. In most situations, it will be appropriate to allow only short alphanumeric strings to be copied into queries, and any other input should be rejected. At a minimum, input containing any LDAP metacharacters should be rejected; characters that should be blocked include ( ) ; , * | & = and whitespace.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/90.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-136: LDAP Injection"#, url: r#"https://capec.mitre.org/data/definitions/136.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1050112,
        declared_type_index: 1050112,
        name: r#"XPath injection"#,
        typical_severity: Severity::High,
        description: r#"<p>XPath injection vulnerabilities arise when user-controllable data is incorporated into XPath queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.</p>
<p>Depending on the purpose for which the vulnerable query is being used, an attacker may be able to exploit an XPath injection flaw to read sensitive application data or interfere with application logic. </p>"#,
        remediation: Some(r#"<p>User input should be strictly validated before being 
  incorporated into XPath queries. 
  In most cases, it will be appropriate to accept input containing only short 
  alphanumeric strings. At the very least, input containing any XPath metacharacters 
  such as " ' / @ = * [ ] ( and ) should be rejected.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Client-side XPath injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-xpath-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')
"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/643.html"# },
            Classification { title: r#"CAPEC-83: XPath Injection"#, url: r#"https://capec.mitre.org/data/definitions/83.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1050368,
        declared_type_index: 1050368,
        name: r#"XML injection"#,
        typical_severity: Severity::Medium,
        description: r#"<p>XML or SOAP injection vulnerabilities arise when user input is inserted into a server-side XML document or SOAP message in an unsafe way. It may be possible to use XML metacharacters to modify the structure of the resulting XML. Depending on the function in which the XML is used, it may be possible to interfere with the application's logic, to perform unauthorized actions or access sensitive data.</p>
<p>This kind of vulnerability can be difficult to detect and exploit remotely; you should review the application's response, and the purpose that the relevant input performs within the application's functionality, to determine whether it is indeed vulnerable. </p>"#,
        remediation: Some(r#"<p>The application should validate or sanitize user input before incorporating it into an XML document or SOAP message. It may be possible to block any input containing XML metacharacters such as &lt; and &gt;. Alternatively, these characters can be replaced with the corresponding entities: &amp;lt; and &amp;gt;.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: XXE injection"#, url: r#"https://portswigger.net/web-security/xxe"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-91: XML Injection (aka Blind XPath Injection)"#, url: r#"https://cwe.mitre.org/data/definitions/91.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CWE-611: Improper Restriction of XML External Entity Reference ('XXE')"#, url: r#"https://cwe.mitre.org/data/definitions/611.html"# },
            Classification { title: r#"CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')"#, url: r#"https://cwe.mitre.org/data/definitions/776.html"# },
            Classification { title: r#"CAPEC-250: XML Injection"#, url: r#"https://capec.mitre.org/data/definitions/250.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1050624,
        declared_type_index: 1050624,
        name: r#"ASP.NET debugging enabled"#,
        typical_severity: Severity::Medium,
        description: r#"<p>ASP.NET allows remote debugging of web applications, if configured to do so. By default, debugging is subject to access control and requires platform-level authentication. </p>
<p>If an attacker can successfully start a remote debugging session, this is likely to disclose sensitive information about the web application and supporting infrastructure that may be valuable in formulating targeted attacks against the system. </p>"#,
        remediation: Some(r#"<p>To disable debugging, open the Web.config file for the application, and find the &lt;compilation&gt; element within the &lt;system.web&gt; section. Set the debug attribute to "false". Note that it is also possible to enable debugging for all applications within the Machine.config file. You should confirm that the debug attribute in the &lt;compilation&gt; element has not been set to "true" within the Machine.config file.</p>
<p>It is strongly recommended that you refer to your platform's documentation relating to this issue, and do not rely solely on the above remediation. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-11: ASP.NET Misconfiguration: Creating Debug Binary"#, url: r#"https://cwe.mitre.org/data/definitions/11.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1050704,
        declared_type_index: 1050704,
        name: r#"Broken access control"#,
        typical_severity: Severity::Info,
        description: r#"<p>Access control is the application of constraints on who or what is authorized to perform actions or access resources.</p>
<p>Broken access controls often present a serious security vulnerability as they can allow attackers to access resources or perform actions they should not be able to.</p>"#,
        remediation: Some(r#"<p>
    If this endpoint is intended to be restricted to authenticated users, implement access controls that enforce this.
</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Access Control"#, url: r#"https://portswigger.net/web-security/access-control"# },
            Reference { title: r#"OWASP A01:2021 - Broken Access Control"#, url: r#"https://owasp.org/Top10/A01_2021-Broken_Access_Control/"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-284: Improper Access Control"#, url: r#"https://cwe.mitre.org/data/definitions/284.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1050880,
        declared_type_index: 1050880,
        name: r#"HTTP PUT method is enabled"#,
        typical_severity: Severity::High,
        description: r#"<p>The HTTP PUT method is normally used to upload data that is saved on the server at a user-supplied URL. If enabled, an attacker may be able to place arbitrary, and potentially malicious, content into the application. Depending on the server's configuration, this may lead to compromise of other users (by uploading client-executable scripts), compromise of the server (by uploading server-executable code), or other attacks.</p>"#,
        remediation: Some(r#"<p>Refer to your platform's documentation to determine how to disable the HTTP PUT method on the server.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-650: Trusting HTTP Permission Methods on the Server Side
"#, url: r#"https://cwe.mitre.org/data/definitions/650.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1051136,
        declared_type_index: 1051136,
        name: r#"Out-of-band resource load (HTTP)"#,
        typical_severity: Severity::High,
        description: r#"<p>Out-of-band resource load arises when it is possible to induce an application to fetch content from an arbitrary external location, and incorporate that content into the application's own response(s). The ability to trigger arbitrary out-of-band resource load does not constitute a vulnerability in its own right, and in some cases might even be the intended behavior of the application. 
However, in many cases, it can indicate a vulnerability with serious consequences.</p>
<p>The ability to request and retrieve web content from other systems can allow the application server to be used as a two-way attack proxy. 
  By submitting suitable payloads, an attacker can cause the application server to attack, or retrieve content from, other systems that it can interact with. 
  This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. 
  Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers.</p>
<p>Additionally, the application's processing of web content that is retrieved from arbitrary URLs exposes some important and non-conventional attack surface. 
  An attacker can deploy a web server that returns malicious content, and then induce the application to retrieve and process that content. 
  This processing might give rise to the types of input-based vulnerabilities that are normally found when unexpected input is submitted directly in requests to the application. 
  The out-of-band attack surface that the application exposes should be thoroughly tested for these types of vulnerabilities. </p>"#,
        remediation: Some(r#"<p>You should review the purpose and intended use of the relevant application functionality, and determine whether the ability to trigger arbitrary out-of-band resource load is intended behavior. 
  If so, you should be aware of the types of attacks that can be performed via this behavior and take appropriate measures. 
  These measures might include blocking network access from the application server to other internal systems, and hardening the application server itself to remove any services available on the local loopback adapter. 
You should also ensure that content retrieved from other systems is processed in a safe manner, with the usual precautions that are applicable when processing input from direct incoming web requests.</p>
<p>If the ability to trigger arbitrary out-of-band resource load is not intended behavior, then you should implement a whitelist of permitted URLs, and block requests to URLs that do not appear on this whitelist.</p>"#),
        references: &[
            Reference { title: r#"Burp Collaborator"#, url: r#"https://portswigger.net/blog/introducing-burp-collaborator"# },
            Reference { title: r#"Out-of-band application security testing (OAST)"#, url: r#"https://portswigger.net/burp/application-security-testing/oast"# },
            Reference { title: r#"PortSwigger Research: Cracking the Lens"#, url: r#"https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-610: Externally Controlled Reference to a Resource in Another Sphere"#, url: r#"https://cwe.mitre.org/data/definitions/610.html"# },
            Classification { title: r#"CWE-918: Server-Side Request Forgery (SSRF)"#, url: r#"https://cwe.mitre.org/data/definitions/918.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1051392,
        declared_type_index: 1051392,
        name: r#"File path manipulation"#,
        typical_severity: Severity::High,
        description: r#"<p>File path manipulation vulnerabilities arise when user-controllable data is placed into a file or URL path that is used on the server to access local resources, which may be within or outside the web root. If vulnerable, an attacker can modify the file path to access different resources, which may contain sensitive information. Even where an attack is constrained within the web root, it is often possible to retrieve items that are normally protected from direct access, such as application configuration files, the source code for server-executable scripts, or files with extensions that the web server is not configured to serve directly.</p>"#,
        remediation: Some(r#"<p>Ideally, application functionality should be designed in such a way that user-controllable data does not need to be placed into file or URL paths in order to access local resources on the server. This can normally be achieved by referencing known files via an index number rather than their name.</p>
<p>If it is considered unavoidable to place user data into file or URL paths, the data should be strictly validated against a whitelist of accepted values. Note that when accessing resources within the web root, simply blocking input containing file path traversal sequences (such as dot-dot-slash) is not always sufficient to prevent retrieval of sensitive information, because some protected items may be accessible at the original path without using any traversal sequences. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Directory traversal"#, url: r#"https://portswigger.net/web-security/file-path-traversal"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"#, url: r#"https://cwe.mitre.org/data/definitions/22.html"# },
            Classification { title: r#"CWE-23: Relative Path Traversal"#, url: r#"https://cwe.mitre.org/data/definitions/23.html"# },
            Classification { title: r#"CWE-35: Path Traversal: '.../...//'"#, url: r#"https://cwe.mitre.org/data/definitions/35.html"# },
            Classification { title: r#"CWE-36: Absolute Path Traversal"#, url: r#"https://cwe.mitre.org/data/definitions/36.html"# },
            Classification { title: r#"CAPEC-126: Path Traversal"#, url: r#"https://capec.mitre.org/data/definitions/126.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1051648,
        declared_type_index: 1051648,
        name: r#"PHP code injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Server-side code injection vulnerabilities arise when an application 
  incorporates user-controllable data into a string that is dynamically evaluated by 
  a code interpreter. If the user data is not strictly validated, an attacker 
  can use crafted input to modify the code to be executed, and inject 
  arbitrary code that will be executed by the server.</p>
<p>Server-side code injection vulnerabilities are usually very serious and lead to 
  complete compromise of the application's 
  data and functionality, and often of the server that is hosting the application.
  It may also be possible to use the server as a platform for further attacks against other systems.</p>"#,
        remediation: Some(r#"<p>Whenever possible, applications should avoid incorporating user-controllable data into 
  dynamically evaluated code. In almost every situation, there are safer alternative 
  methods of implementing application functions, which cannot be 
  manipulated to inject arbitrary code into the server's processing.</p>
<p>If it is considered unavoidable to incorporate user-supplied data into 
  dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted 
  values should be used. Otherwise, only short alphanumeric strings should be accepted. 
  Input containing any other data, including any conceivable code metacharacters, should be rejected. </p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')
"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-193: PHP Remote File Inclusion"#, url: r#"https://capec.mitre.org/data/definitions/193.html"# },
            Classification { title: r#"CAPEC-242: Code Injection"#, url: r#"https://capec.mitre.org/data/definitions/242.html"# },
            Classification { title: r#"CAPEC-252: PHP Local File Inclusion"#, url: r#"https://capec.mitre.org/data/definitions/252.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1051904,
        declared_type_index: 1051904,
        name: r#"Server-side JavaScript code injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Server-side code injection vulnerabilities arise when an application 
  incorporates user-controllable data into a string that is dynamically evaluated by 
  a code interpreter. If the user data is not strictly validated, an attacker 
  can use crafted input to modify the code to be executed, and inject 
  arbitrary code that will be executed by the server.</p>
<p>Server-side code injection vulnerabilities are usually very serious and lead to 
  complete compromise of the application's 
  data and functionality, and often of the server that is hosting the application.
  It may also be possible to use the server as a platform for further attacks against other systems.</p>"#,
        remediation: Some(r#"<p>Whenever possible, applications should avoid incorporating user-controllable data into 
  dynamically evaluated code. In almost every situation, there are safer alternative 
  methods of implementing application functions, which cannot be 
  manipulated to inject arbitrary code into the server's processing.</p>
<p>If it is considered unavoidable to incorporate user-supplied data into 
  dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted 
  values should be used. Otherwise, only short alphanumeric strings should be accepted. 
  Input containing any other data, including any conceivable code metacharacters, should be rejected. </p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-242: Code Injection"#, url: r#"https://capec.mitre.org/data/definitions/242.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1052160,
        declared_type_index: 1052160,
        name: r#"Perl code injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Server-side code injection vulnerabilities arise when an application 
  incorporates user-controllable data into a string that is dynamically evaluated by 
  a code interpreter. If the user data is not strictly validated, an attacker 
  can use crafted input to modify the code to be executed, and inject 
  arbitrary code that will be executed by the server.</p>
<p>Server-side code injection vulnerabilities are usually very serious and lead to 
  complete compromise of the application's 
  data and functionality, and often of the server that is hosting the application.
  It may also be possible to use the server as a platform for further attacks against other systems.</p>"#,
        remediation: Some(r#"<p>Whenever possible, applications should avoid incorporating user-controllable data into 
  dynamically evaluated code. In almost every situation, there are safer alternative 
  methods of implementing application functions, which cannot be 
  manipulated to inject arbitrary code into the server's processing.</p>
<p>If it is considered unavoidable to incorporate user-supplied data into 
  dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted 
  values should be used. Otherwise, only short alphanumeric strings should be accepted. 
  Input containing any other data, including any conceivable code metacharacters, should be rejected. </p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-242: Code Injection"#, url: r#"https://capec.mitre.org/data/definitions/242.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1052416,
        declared_type_index: 1052416,
        name: r#"Ruby code injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Server-side code injection vulnerabilities arise when an application 
  incorporates user-controllable data into a string that is dynamically evaluated by 
  a code interpreter. If the user data is not strictly validated, an attacker 
  can use crafted input to modify the code to be executed, and inject 
  arbitrary code that will be executed by the server.</p>
<p>Server-side code injection vulnerabilities are usually very serious and lead to 
  complete compromise of the application's 
  data and functionality, and often of the server that is hosting the application.
  It may also be possible to use the server as a platform for further attacks against other systems.</p>"#,
        remediation: Some(r#"<p>Whenever possible, applications should avoid incorporating user-controllable data into 
  dynamically evaluated code. In almost every situation, there are safer alternative 
  methods of implementing application functions, which cannot be 
  manipulated to inject arbitrary code into the server's processing.</p>
<p>If it is considered unavoidable to incorporate user-supplied data into 
  dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted 
  values should be used. Otherwise, only short alphanumeric strings should be accepted. 
  Input containing any other data, including any conceivable code metacharacters, should be rejected. </p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-242: Code Injection"#, url: r#"https://capec.mitre.org/data/definitions/242.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1052432,
        declared_type_index: 1052432,
        name: r#"Python code injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Server-side code injection vulnerabilities arise when an application 
  incorporates user-controllable data into a string that is dynamically evaluated by 
  a code interpreter. If the user data is not strictly validated, an attacker 
  can use crafted input to modify the code to be executed, and inject 
  arbitrary code that will be executed by the server.</p>
<p>Server-side code injection vulnerabilities are usually very serious and lead to 
  complete compromise of the application's 
  data and functionality, and often of the server that is hosting the application.
  It may also be possible to use the server as a platform for further attacks against other systems.</p>"#,
        remediation: Some(r#"<p>Whenever possible, applications should avoid incorporating user-controllable data into 
  dynamically evaluated code. In almost every situation, there are safer alternative 
  methods of implementing application functions, which cannot be 
  manipulated to inject arbitrary code into the server's processing.</p>
<p>If it is considered unavoidable to incorporate user-supplied data into 
  dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted 
  values should be used. Otherwise, only short alphanumeric strings should be accepted. 
  Input containing any other data, including any conceivable code metacharacters, should be rejected. </p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-242: Code Injection"#, url: r#"https://capec.mitre.org/data/definitions/242.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1052448,
        declared_type_index: 1052448,
        name: r#"Expression Language injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Server-side code injection vulnerabilities arise when an application 
  incorporates user-controllable data into a string that is dynamically evaluated by 
  a code interpreter. If the user data is not strictly validated, an attacker 
  can use crafted input to modify the code to be executed, and inject 
  arbitrary code that will be executed by the server.</p>
<p>Server-side code injection vulnerabilities are usually very serious and lead to 
  complete compromise of the application's 
  data and functionality, and often of the server that is hosting the application.
  It may also be possible to use the server as a platform for further attacks against other systems.</p>"#,
        remediation: Some(r#"<p>Whenever possible, applications should avoid incorporating user-controllable data into 
  dynamically evaluated code. In almost every situation, there are safer alternative 
  methods of implementing application functions, which cannot be 
  manipulated to inject arbitrary code into the server's processing.</p>
<p>If it is considered unavoidable to incorporate user-supplied data into 
  dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted 
  values should be used. Otherwise, only short alphanumeric strings should be accepted. 
  Input containing any other data, including any conceivable code metacharacters, should be rejected. </p>"#),
        references: &[
            Reference { title: r#"Spring Expression Language Injection"#, url: r#"https://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf"# },
            Reference { title: r#"Remote Code Execution with Spring Expression Language Injection"#, url: r#"http://danamodio.com/appsec/research/spring-remote-code-with-expression-language-injection/"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/917.html"# },
            Classification { title: r#"CAPEC-242: Code Injection"#, url: r#"https://capec.mitre.org/data/definitions/242.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1052672,
        declared_type_index: 1052672,
        name: r#"Unidentified code injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Server-side code injection vulnerabilities arise when an application 
  incorporates user-controllable data into a string that is dynamically evaluated by 
  a code interpreter. If the user data is not strictly validated, an attacker 
  can use crafted input to modify the code to be executed, and inject 
  arbitrary code that will be executed by the server.</p>
<p>Server-side code injection vulnerabilities are usually very serious and lead to 
  complete compromise of the application's 
  data and functionality, and often of the server that is hosting the application.
  It may also be possible to use the server as a platform for further attacks against other systems.</p>"#,
        remediation: Some(r#"<p>Whenever possible, applications should avoid incorporating user-controllable data into 
  dynamically evaluated code. In almost every situation, there are safer alternative 
  methods of implementing application functions, which cannot be 
  manipulated to inject arbitrary code into the server's processing.</p>
<p>If it is considered unavoidable to incorporate user-supplied data into 
  dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted 
  values should be used. Otherwise, only short alphanumeric strings should be accepted. 
  Input containing any other data, including any conceivable code metacharacters, should be rejected. </p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-242: Code Injection"#, url: r#"https://capec.mitre.org/data/definitions/242.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1052800,
        declared_type_index: 1052800,
        name: r#"Server-side template injection"#,
        typical_severity: Severity::High,
        description: r#"<p> Server-side template injection occurs when user input is unsafely embedded into a server-side template, allowing users to inject template directives. Using malicious template directives, an attacker may be able to execute arbitrary code and take full control of the web server. </p>
<p>The severity of this issue varies depending on the type of template engine being used. Template engines range from being trivial to almost impossible to exploit. The following  steps should be used when attempting to develop an exploit: </p><ul>
  <li>Identify the type of template engine being used.</li>
  <li>Review its documentation for basic syntax, security considerations, and built-in methods and variables.</li>
  <li>Explore the template environment and map the attack surface.</li>
<li>Audit every exposed object and method.</li>
</ul>
<p>
Template injection vulnerabilities can be very serious and can lead to complete compromise of the application's data and functionality, and often of the server that is hosting the application. It may also be possible to use the server as a platform for further attacks against other systems. On the other hand, some template injection vulnerabilities may pose no significant security risk.
</p>"#,
        remediation: Some(r#"<p>Wherever possible, avoid creating templates from user input. Passing user input into templates as parameters is normally a safe alternative.</p>
<p>If supporting user-submitted templates is a business requirement, consider using a simple logic-less template engine such as Mustache or one provided by the native language like Python's Template. If this is not an option, review the chosen template engine's documentation for hardening advice, and consider rendering the template within a sandboxed execution environment.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Server-side template injection"#, url: r#"https://portswigger.net/web-security/server-side-template-injection"# },
            Reference { title: r#"Server-side template injection"#, url: r#"https://portswigger.net/research/server-side-template-injection"# },
            Reference { title: r#"FreeMarker hardening"#, url: r#"http://freemarker.org/docs/app_faq.html#faq_template_uploading_security"# },
            Reference { title: r#"Velocity Hardening"#, url: r#"https://velocity.apache.org/engine/devel/apidocs/org/apache/velocity/util/introspection/SecureUberspector.html"# },
            Reference { title: r#"Twig hardening"#, url: r#"http://twig.sensiolabs.org/doc/api.html#sandbox-extension"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1052928,
        declared_type_index: 1052928,
        name: r#"SSI injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Server-Side Include (SSI) injection vulnerabilities arise when an application incorporates user-controllable data into response that is then parsed for Server-Side Include directives. If the data is not strictly validated, an attacker can modify or inject directives to carry out malicious actions.</p>
<p>SSI injection vulnerabilities can typically be exploited to inject arbitrary content, including JavaScript, into the application's response, with the same impact as cross-site scripting. Depending on the server configuration, it may also be possible to read protected files, or perform arbitrary code execution on the server, with the same impact as OS command injection. </p>"#,
        remediation: Some(r#"<p>If possible, applications should avoid incorporating user-controllable data into pages that are processed for SSI directives. In almost every situation, there are safer alternative methods of implementing the required functionality. If this is not considered feasible, then the data should be strictly validated. Ideally, a whitelist of specific accepted values should be used. Otherwise, only short alphanumeric strings should be accepted. Input containing any other data, including any conceivable SSI metacharacter, should be rejected.</p>"#),
        references: &[
            Reference { title: r#"Introduction to Server-Side Includes"#, url: r#"http://httpd.apache.org/docs/current/howto/ssi.html"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/96.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-101: Server Side Include (SSI) Injection"#, url: r#"https://capec.mitre.org/data/definitions/101.html"# },
        ],
    },
    IssueDefinition {
        type_index: 1053184,
        declared_type_index: 1052160,
        name: r#"React Server Components remote code execution (React2Shell)"#,
        typical_severity: Severity::High,
        description: r#"<p>The application is vulnerable to <b>CVE-2025-55182</b> (React) and <b>CVE-2025-66478</b> (Next.js), critical Remote Code Execution vulnerabilities in React Server Components with CVSS score of 10.0.</p><p><b>Vulnerability Overview:</b></p><ul><li>Unauthenticated Remote Code Execution via insecure deserialization</li><li>The RSC Flight protocol fails to validate property existence in colon-delimited references</li><li>Malformed multipart form-data triggers unhandled exceptions leading to RCE</li><li>No prerequisites or special configuration required for exploitation</li></ul>"#,
        remediation: Some(r#"<p><b>CRITICAL - Immediate Action Required</b></p><p>This vulnerability allows unauthenticated attackers to execute arbitrary code on the server. Patch immediately.</p><p><b>Upgrade to Patched Versions:</b></p><ul><li><b>React:</b> 19.0.1, 19.1.2, or 19.2.1</li><li><b>Next.js:</b> 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, or 16.0.7</li></ul><p><b>Remediation Steps:</b></p><ol><li>Update package.json dependencies to patched versions</li><li>Run npm install or npm update</li><li>Rebuild and redeploy application</li><li>Verify fix by re-scanning</li></ol>"#),
        references: &[
            Reference { title: r#"Next.js Security Advisory"#, url: r#"https://nextjs.org/blog/CVE-2025-66478"# },
            Reference { title: r#"CVE-2025-55182 Details"#, url: r#"https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182"# },
            Reference { title: r#"Detection of CVE-2025-55182"#, url: r#"https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478/"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-502: Deserialization of Untrusted Data"#, url: r#"https://cwe.mitre.org/data/definitions/502.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097408,
        declared_type_index: 2097408,
        name: r#"Cross-site scripting (stored)"#,
        typical_severity: Severity::High,
        description: r#"<p>Stored cross-site scripting vulnerabilities arise when user input is stored and later embedded into the application's responses in an unsafe way. An attacker can use the vulnerability to inject malicious JavaScript code into the application, which will execute within the browser of any user who views the relevant application content.</p>
<p>The attacker-supplied code can perform a wide variety of actions, such as stealing victims' session tokens or login credentials, performing arbitrary actions on their behalf, and logging their keystrokes.</p>
<p>Methods for introducing malicious content include any function where request parameters or headers are processed and stored by the application, and any out-of-band channel whereby data can be introduced into the application's processing space (for example, email messages sent over SMTP that are ultimately rendered within a web mail application).</p>
<p>Stored cross-site scripting flaws are typically more serious than reflected vulnerabilities because they do not require a separate delivery mechanism in order to reach target users, and are not hindered by web browsers' XSS filters. Depending on the affected page, ordinary users may be exploited during normal use of the application. In some situations this can be used to create web application worms that spread exponentially and ultimately exploit all active users.</p>
<p>Note that automated detection of stored cross-site scripting vulnerabilities cannot reliably determine whether attacks that are persisted within the application can be accessed by any other user, only by authenticated users, or only by the attacker themselves. You should review the functionality in which the vulnerability appears to determine whether the application's behavior can feasibly be used to compromise other application users. </p>"#,
        remediation: Some(r#"<p>In most situations where user-controllable data is copied into application responses, cross-site scripting 
  attacks can be prevented using two layers of defenses:</p>
<ul>
  <li>Input should be validated as strictly as possible on arrival, given the kind of content that 
it is expected to contain. For example, personal names should consist of alphabetical 
and a small range of typographical characters, and be relatively short; a year of birth 
should consist of exactly four numerals; email addresses should match a well-defined 
regular expression. Input which fails the validation should be rejected, not sanitized.</li>
<li>User input should be HTML-encoded at any point where it is copied into 
application responses. All HTML metacharacters, including &lt; &gt; " ' and =, should be 
replaced with the corresponding HTML entities (&amp;lt; &amp;gt; etc).</li></ul>
<p>In cases where the application's functionality allows users to author content using 
  a restricted subset of HTML tags and attributes (for example, blog comments which 
  allow limited formatting and linking), it is necessary to parse the supplied HTML to 
  validate that it does not use any dangerous syntax; this is a non-trivial task.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
            Reference { title: r#"Web Security Academy: Stored cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/stored"# },
            Reference { title: r#"Using Burp to Find XSS issues"#, url: r#"https://support.portswigger.net/customer/portal/articles/1965737-Methodology_XSS.html"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)"#, url: r#"https://cwe.mitre.org/data/definitions/80.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-592: Stored XSS"#, url: r#"https://capec.mitre.org/data/definitions/592.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097472,
        declared_type_index: 2097472,
        name: r#"HTTP request smuggling"#,
        typical_severity: Severity::High,
        description: r#"<p>
    HTTP request smuggling vulnerabilities arise when websites route HTTP requests through web servers with inconsistent HTTP parsing.
</p>
<p>
    By supplying a request that different servers interpret as having different lengths, an attacker can poison the back-end TCP/TLS socket and prepend arbitrary data to the next request. Depending on the website's functionality, this can be used to bypass front-end security rules, access internal systems, poison web caches, and launch assorted attacks on users who are actively browsing the site.
</p>"#,
        remediation: Some(r#"<p>
    You can resolve all variants of this vulnerability by configuring the front-end server to exclusively use HTTP/2 when communicating with back-end systems. Alternatively, you could ensure all servers in the chain run the same web server software with the same configuration. Disabling back-end connection reuse is likely to reduce the impact of this vulnerability, but does not mitigate all possible exploits.
</p><p>
    Specific instances of this vulnerability can be resolved by reconfiguring the front-end server to normalize ambiguous requests before routing them onward. Alternatively, you could configure the back-end server to reject the message and close the connection when it encounters an ambiguous request.
</p>"#),
        references: &[
            Reference { title: r#"HTTP Request Smuggling"#, url: r#"https://portswigger.net/web-security/request-smuggling"# },
            Reference { title: r#"HTTP Desync Attacks"#, url: r#"https://portswigger.net/blog/http-desync-attacks"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')"#, url: r#"https://cwe.mitre.org/data/definitions/444.html"# },
            Classification { title: r#"CAPEC-33: HTTP Request Smuggling"#, url: r#"https://capec.mitre.org/data/definitions/33.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097473,
        declared_type_index: 2097473,
        name: r#"Client-side desync"#,
        typical_severity: Severity::High,
        description: r#"<p>
    Client-side desync (CSD) vulnerabilities occur when a web server fails to correctly process the Content-Length of POST requests. By exploiting this behavior, an attacker can force a victim's browser to desynchronize its connection with the website, typically leading to XSS.
</p>"#,
        remediation: Some(r#"<p>
    You can resolve this vulnerability by patching the server so that it either processes POST requests correctly, or closes the connection after handling them. You could also disable connection reuse entirely, but this may reduce performance.

    You can also resolve this issue by enabling HTTP/2.
</p>"#),
        references: &[
            Reference { title: r#"HTTP Request Smuggling"#, url: r#"https://portswigger.net/web-security/request-smuggling"# },
            Reference { title: r#"Browser-Powered Desync Attacks"#, url: r#"https://portswigger.net/research/browser-powered-desync-attacks"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')"#, url: r#"https://cwe.mitre.org/data/definitions/444.html"# },
            Classification { title: r#"CAPEC-33: HTTP Request Smuggling"#, url: r#"https://capec.mitre.org/data/definitions/33.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097536,
        declared_type_index: 2097536,
        name: r#"Web cache poisoning"#,
        typical_severity: Severity::High,
        description: r#"<p>Web caches identify resources using a few specific components of each HTTP request, together known as the cache key. Two requests with the same cache key are regarded by the cache as equivalent. </p>
<p>
Web cache poisoning vulnerabilities arise when an application behind a cache processes input that is not included in the cache key. Attackers can exploit this by sending crafted input to trigger a harmful response that the cache will then save and serve to other users.
</p>
<p>
The impact is potentially serious as the malicious cached page may be served to a large number of users without other interaction. The threat posed by this vulnerability depends largely on what can be achieved with the input. Often the input is vulnerable to XSS, or can be used to trigger a redirect to another domain. Other times, it can simply be used to swap pages around.
</p>"#,
        remediation: Some(r#"<p>To resolve this issue, either disable support for the affected input, or disable caching on all affected pages.</p>
<p>If both the affected input and caching behavior are required, configure the cache to ensure that the input is included in the cache key. Depending on which caching solution you use, if the input is in a request header it might be possible to achieve this using the Vary response header.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Web cache poisoning"#, url: r#"https://portswigger.net/web-security/web-cache-poisoning"# },
            Reference { title: r#"PortSwigger Research: Practical Web Cache Poisoning"#, url: r#"https://portswigger.net/research/web-cache-poisoning"# },
            Reference { title: r#"PortSwigger Research: Web Cache Entanglement"#, url: r#"https://portswigger.net/research/web-cache-entanglement-novel-pathways-to-poisoning"# },
            Reference { title: r#"HTTP Vary header"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-436: Interpretation Conflict"#, url: r#"https://cwe.mitre.org/data/definitions/436.html"# },
            Classification { title: r#"CAPEC-141: Cache Poisoning"#, url: r#"https://capec.mitre.org/data/definitions/141.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097664,
        declared_type_index: 2097664,
        name: r#"HTTP response header injection"#,
        typical_severity: Severity::High,
        description: r#"<p>HTTP response header injection vulnerabilities arise when user-supplied data is copied into a response header in an unsafe way. If an attacker can inject newline characters into the header, then they can inject new HTTP headers and also, by injecting an empty line, break out of the headers into the message body and write arbitrary content into the application's response.</p>
<p>Various kinds of attack can be delivered via HTTP response header injection vulnerabilities. Any attack that can be delivered via cross-site scripting can usually be delivered via response header injection, because the attacker can construct a request that causes arbitrary JavaScript to appear within the response body. Further, it is sometimes possible to leverage response header injection vulnerabilities to poison the cache of any proxy server via which users access the application. Here, an attacker sends a crafted request that results in a "split" response containing arbitrary content. If the proxy server can be manipulated to associate the injected response with another URL used within the application, then the attacker can perform a "stored" attack against this URL, which will compromise other users who request that URL in future.
</p>"#,
        remediation: Some(r#"<p>If possible, applications should avoid copying user-controllable data into HTTP response headers. If this is unavoidable, then the data should be strictly validated to prevent response header injection attacks. In most situations, it will be appropriate to allow only short alphanumeric strings to be copied into headers, and any other input should be rejected. At a minimum, input containing any characters with ASCII codes less than 0x20 should be rejected.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')"#, url: r#"https://cwe.mitre.org/data/definitions/113.html"# },
            Classification { title: r#"CAPEC-34: HTTP Response Splitting"#, url: r#"https://capec.mitre.org/data/definitions/34.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097920,
        declared_type_index: 2097920,
        name: r#"Cross-site scripting (reflected)"#,
        typical_severity: Severity::High,
        description: r#"<p>Reflected cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's immediate response in an unsafe way. An attacker can use the vulnerability to construct a request that, if issued by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.</p>
<p>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.</p>
<p>Users can be induced to issue the attacker's crafted request in various ways. For example, the attacker can send a victim a link containing a malicious URL in an email or instant message. They can submit the link to popular web sites that allow content authoring, for example in blog comments. And they can create an innocuous looking web site that causes anyone viewing it to make arbitrary cross-domain requests to the vulnerable application (using either the GET or the POST method).</p>
<p>The security impact of cross-site scripting vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality that it contains, and the other applications that belong to the same domain and organization. If the application is used only to display non-sensitive public content, with no authentication or access control functionality, then a cross-site scripting flaw may be considered low risk. However, if the same application resides on a domain that can access cookies for other more security-critical applications, then the vulnerability could be used to attack those other applications, and so may be considered high risk. Similarly, if the organization that owns the application is a likely target for phishing attacks, then the vulnerability could be leveraged to lend credibility to such attacks, by injecting Trojan functionality into the vulnerable application and exploiting users' trust in the organization in order to capture credentials for other applications that it owns. In many kinds of application, such as those providing online banking functionality, cross-site scripting should always be considered high risk. </p>"#,
        remediation: Some(r#"<p>In most situations where user-controllable data is copied into application responses, cross-site scripting 
  attacks can be prevented using two layers of defenses:</p>
<ul>
  <li>Input should be validated as strictly as possible on arrival, given the kind of content that 
it is expected to contain. For example, personal names should consist of alphabetical 
and a small range of typographical characters, and be relatively short; a year of birth 
should consist of exactly four numerals; email addresses should match a well-defined 
regular expression. Input which fails the validation should be rejected, not sanitized.</li>
<li>User input should be HTML-encoded at any point where it is copied into 
application responses. All HTML metacharacters, including &lt; &gt; " ' and =, should be 
replaced with the corresponding HTML entities (&amp;lt; &amp;gt; etc).</li></ul>
<p>In cases where the application's functionality allows users to author content using 
  a restricted subset of HTML tags and attributes (for example, blog comments which 
  allow limited formatting and linking), it is necessary to parse the supplied HTML to 
  validate that it does not use any dangerous syntax; this is a non-trivial task.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
            Reference { title: r#"Web Security Academy: Reflected cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/reflected"# },
            Reference { title: r#"Using Burp to Find XSS issues"#, url: r#"https://support.portswigger.net/customer/portal/articles/1965737-Methodology_XSS.html"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)"#, url: r#"https://cwe.mitre.org/data/definitions/80.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-591: Reflected XSS"#, url: r#"https://capec.mitre.org/data/definitions/591.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097928,
        declared_type_index: 2097928,
        name: r#"Client-side template injection"#,
        typical_severity: Severity::High,
        description: r#"<p>Client-side template injection vulnerabilities arise when applications using a client-side template framework dynamically embed user input in web pages. When a web page is rendered, the framework will scan the page for template expressions, and execute any that it encounters. An attacker can exploit this by supplying a malicious template expression that launches a cross-site scripting (XSS) attack. As with normal cross-site scripting, the attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.</p>
<p>Users can be induced to issue the attacker's crafted request in various ways. For example, the attacker can send a victim a link containing a malicious URL in an email or instant message. They can submit the link to popular web sites that allow content authoring, for example in blog comments. And they can create an innocuous looking web site that causes anyone viewing it to make arbitrary cross-domain requests to the vulnerable application (using either the GET or the POST method).</p>
<p>The security impact of client-side template injection vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality that it contains, and the other applications that belong to the same domain and organization. If the application is used only to display non-sensitive public content, with no authentication or access control functionality, then a client-side template injection flaw may be considered low risk. However, if the same application resides on a domain that can access cookies for other more security-critical applications, then the vulnerability could be used to attack those other applications, and so may be considered high risk. Similarly, if the organization that owns the application is a likely target for phishing attacks, then the vulnerability could be leveraged to lend credibility to such attacks, by injecting Trojan functionality into the vulnerable application and exploiting users' trust in the organization in order to capture credentials for other applications that it owns. In many kinds of application, such as those providing online banking functionality, client-side template injection should always be considered high risk. </p>
<p>Client-side template frameworks often implement a sandbox aimed at hindering direct execution of arbitrary JavaScript from within a template expression. However, these sandboxes are not intended to be a security control and can normally be bypassed.</p>
<p>Browser cross-site scripting filters are typically unable to detect or prevent client-side template injection attacks.</p>"#,
        remediation: Some(r#"<p>If possible, avoid using server-side code to dynamically embed user input into client-side templates. If this is not practical, consider filtering out template expression syntax from user input prior to embedding it within client-side templates. </p>
<p>Note that HTML-encoding is not sufficient to prevent client-side template injection attacks, because frameworks perform an HTML-decode of relevant content prior to locating and executing template expressions.</p>"#),
        references: &[
            Reference { title: r#"XSS without HTML: Client-Side Template Injection with AngularJS"#, url: r#"https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs"# },
            Reference { title: r#"Web Security Academy: AngularJS sandbox escapes"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox"# },
            Reference { title: r#"AngularJS Security Considerations"#, url: r#"https://docs.angularjs.org/guide/security"# },
            Reference { title: r#"JavaScript MVC Security Pitfalls"#, url: r#"https://code.google.com/p/mustache-security/"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-588: DOM-Based XSS"#, url: r#"https://capec.mitre.org/data/definitions/588.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097936,
        declared_type_index: 2097936,
        name: r#"Cross-site scripting (DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>
<p>DOM-based cross-site scripting arises when a script  writes controllable data into the HTML document in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.</p>
<p>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.</p>
<p>Users can be induced to visit the attacker's crafted URL in various ways, similar to the usual attack delivery vectors for reflected cross-site scripting vulnerabilities.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based cross-site scripting vulnerabilities is not to dynamically write data from any untrusted source into the HTML document. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing script code into the document. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. In other cases, it will be necessary to sanitize or encode the data. This can be a complex task, and depending on the context that the data is to be inserted may need to involve a combination of JavaScript escaping, HTML encoding, and URL encoding, in the appropriate sequence. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
            Reference { title: r#"Web Security Academy: DOM-based cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/dom-based"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)"#, url: r#"https://cwe.mitre.org/data/definitions/80.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-588: DOM-Based XSS"#, url: r#"https://capec.mitre.org/data/definitions/588.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097937,
        declared_type_index: 2097937,
        name: r#"Cross-site scripting (reflected DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM-based cross-site scripting arises when a script  writes controllable data into the HTML document in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.</p>
<p>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.</p>
<p>Users can be induced to visit the attacker's crafted URL in various ways, similar to the usual attack delivery vectors for reflected cross-site scripting vulnerabilities.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based cross-site scripting vulnerabilities is not to dynamically write data from any untrusted source into the HTML document. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing script code into the document. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. In other cases, it will be necessary to sanitize or encode the data. This can be a complex task, and depending on the context that the data is to be inserted may need to involve a combination of JavaScript escaping, HTML encoding, and URL encoding, in the appropriate sequence. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
            Reference { title: r#"Web Security Academy: Reflected cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/reflected"# },
            Reference { title: r#"Web Security Academy: DOM-based cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/dom-based"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)"#, url: r#"https://cwe.mitre.org/data/definitions/80.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-591: Reflected XSS"#, url: r#"https://capec.mitre.org/data/definitions/591.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097938,
        declared_type_index: 2097938,
        name: r#"Cross-site scripting (stored DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM-based cross-site scripting arises when a script  writes controllable data into the HTML document in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.</p>
<p>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.</p>
<p>Users can be induced to visit the attacker's crafted URL in various ways, similar to the usual attack delivery vectors for reflected cross-site scripting vulnerabilities.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based cross-site scripting vulnerabilities is not to dynamically write data from any untrusted source into the HTML document. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing script code into the document. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. In other cases, it will be necessary to sanitize or encode the data. This can be a complex task, and depending on the context that the data is to be inserted may need to involve a combination of JavaScript escaping, HTML encoding, and URL encoding, in the appropriate sequence. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
            Reference { title: r#"Web Security Academy: Stored cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/stored"# },
            Reference { title: r#"Web Security Academy: DOM-based cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/dom-based"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)"#, url: r#"https://cwe.mitre.org/data/definitions/80.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-592: Stored XSS"#, url: r#"https://capec.mitre.org/data/definitions/592.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097942,
        declared_type_index: 2097942,
        name: r#"Client-side prototype pollution"#,
        typical_severity: Severity::Info,
        description: r#"<p>
    A client-side prototype pollution source is any user-controlled JSON property, query string, or hash parameter that is converted to a JavaScript object and then merged with another object. This enables an attacker to use property keys, such as __proto__, to assign properties to the Object.prototype or other global prototypes.
</p>
<p>
    Client-side prototype pollution is not a vulnerability in its own right. However, when paired with a gadget, this may lead to vulnerabilities such as DOM XSS, which could enable the attacker to control JavaScript on the page.
</p>"#,
        remediation: Some(r#"<p>
    Ensure that property keys, such as __proto__, constructor, and prototype are correctly filtered when merging objects. When creating objects, we recommend using the Object.create(null) API to ensure that your object does not inherit from the Object.prototype and, therefore, won't be vulnerable to prototype pollution.
</p>"#),
        references: &[
            Reference { title: r#"Testing for client-side prototype pollution in DOM Invader"#, url: r#"https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution.html"# },
            Reference { title: r#"Web Security Academy: Prototype pollution"#, url: r#"https://portswigger.net/web-security/prototype-pollution"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"#, url: r#"https://cwe.mitre.org/data/definitions/1321.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097952,
        declared_type_index: 2097952,
        name: r#"JavaScript injection (DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>

<p>DOM-based JavaScript injection arises when a script executes controllable data as JavaScript. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.</p>
<p>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.</p>
<p>Users can be induced to visit the attacker's crafted URL in various ways, similar to the usual attack delivery vectors for reflected cross-site scripting vulnerabilities.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based JavaScript injection vulnerabilities is not to execute as JavaScript any data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from executing as script. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. In other cases, it will be necessary to sanitize or encode the data. This can be a complex task, and may need to involve a combination of JavaScript escaping and HTML encoding, in the appropriate sequence. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: JavaScript injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/javascript-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-63: Cross-Site Scripting (XSS)"#, url: r#"https://capec.mitre.org/data/definitions/63.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097953,
        declared_type_index: 2097953,
        name: r#"JavaScript injection (reflected DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>DOM-based JavaScript injection arises when a script executes controllable data as JavaScript. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.</p>
<p>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.</p>
<p>Users can be induced to visit the attacker's crafted URL in various ways, similar to the usual attack delivery vectors for reflected cross-site scripting vulnerabilities.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based JavaScript injection vulnerabilities is not to execute as JavaScript any data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from executing as script. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. In other cases, it will be necessary to sanitize or encode the data. This can be a complex task, and may need to involve a combination of JavaScript escaping and HTML encoding, in the appropriate sequence. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: JavaScript injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/javascript-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-63: Cross-Site Scripting (XSS)"#, url: r#"https://capec.mitre.org/data/definitions/63.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097954,
        declared_type_index: 2097954,
        name: r#"JavaScript injection (stored DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>DOM-based JavaScript injection arises when a script executes controllable data as JavaScript. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.</p>
<p>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.</p>
<p>Users can be induced to visit the attacker's crafted URL in various ways, similar to the usual attack delivery vectors for reflected cross-site scripting vulnerabilities.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based JavaScript injection vulnerabilities is not to execute as JavaScript any data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from executing as script. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. In other cases, it will be necessary to sanitize or encode the data. This can be a complex task, and may need to involve a combination of JavaScript escaping and HTML encoding, in the appropriate sequence. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: JavaScript injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/javascript-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-94: Improper Control of Generation of Code ('Code Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/95.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-63: Cross-Site Scripting (XSS)"#, url: r#"https://capec.mitre.org/data/definitions/63.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097960,
        declared_type_index: 2097960,
        name: r#"Path-relative style sheet import"#,
        typical_severity: Severity::Info,
        description: r#"<p>Path-relative style sheet import vulnerabilities arise when the following conditions hold:</p>
<ol>
<li>A response contains a style sheet import that uses a path-relative URL (for example, the page at "/original-path/file.php" might import "styles/main.css").</li><li>When handling requests, the application or platform tolerates superfluous path-like data following the original filename in the URL (for example, "/original-path/file.php/extra-junk/"). When superfluous data is added to the original URL, the application's response still contains a path-relative stylesheet import.</li><li>The response in condition 2 can be made to render in a browser's quirks mode, either because it has a missing or old doctype directive, or because it allows itself to be framed by a page under an attacker's control.</li>
<li>When a browser requests the style sheet that is imported in the response from the modified URL (using the URL "/original-path/file.php/extra-junk/styles/main.css"), the application returns something other than the CSS response that was supposed to be imported. Given the behavior described in condition 2, this will typically be the same response that was originally returned in condition 1.</li><li>An attacker has a means of manipulating some text within the response in condition 4, for example because the application stores and displays some past input, or echoes some text within the current URL.</li></ol>
<p>Given the above conditions, an attacker can execute CSS injection within the browser of the target user. The attacker can construct a URL that causes the victim's browser to import as CSS a different URL than normal, containing text that the attacker can manipulate.</p>
<p>Being able to inject arbitrary CSS into the victim's browser may enable various attacks, including:</p>
<ul>
  <li>Executing arbitrary JavaScript using IE's expression() function.</li><li>Using CSS selectors to read parts of the HTML source, which may include sensitive data such as anti-CSRF tokens.</li>
<li>Capturing any sensitive data within the URL query string by making a further style sheet import to a URL on the attacker's domain, and monitoring the incoming Referer header.</li></ul>"#,
        remediation: Some(r#"<p>The root cause of the vulnerability can be resolved by not using path-relative URLs in style sheet imports. Aside from this, attacks can also be prevented by implementing all of the following defensive measures: </p>
<ul><li>Setting the HTTP response header "X-Frame-Options: deny" in all responses. One method that an attacker can use to make a page render in quirks mode is to frame it within their own page that is rendered in quirks mode. Setting this header prevents the page from being framed.</li><li>Setting a modern doctype (e.g. "&lt;!doctype html&gt;") in all HTML responses. This prevents the page from being rendered in quirks mode (unless it is being framed, as described above).</li>
<li>Setting the HTTP response header "X-Content-Type-Options: nosniff" in all responses. This prevents the browser from processing a non-CSS response as CSS, even if another page loads the response via a style sheet import.</li></ul>"#),
        references: &[
            Reference { title: r#"Detecting and exploiting path-relative stylesheet import (PRSSI) vulnerabilities"#, url: r#"https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CAPEC-154: Resource Location Spoofing"#, url: r#"https://capec.mitre.org/data/definitions/154.html"# },
            Classification { title: r#"CAPEC-468: Generic Cross-Browser Cross-Domain Theft"#, url: r#"https://capec.mitre.org/data/definitions/468.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097968,
        declared_type_index: 2097968,
        name: r#"Client-side SQL injection (DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>

<p>Client-side SQL injection arises when a script incorporates controllable  data into a client-side SQL query in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will execute an arbitrary SQL query within the local SQL database of the user's browser.</p>
<p>The potential impact of the vulnerability depends on the application's usage of the SQL database. If the database is used to store sensitive data (such as messages in a social networking application), then the attacker may be able to retrieve this data. If the database is used to store pending user actions (such as outgoing messages in an email application), then the attacker may be able to modify this data and carry out actions on the user's behalf.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based client-side SQL injection vulnerabilities is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. In the JavaScript executeSql() API, parameterized items can be designated within the query string using the query character (?), and for each parameterized item, an additional parameter is passed to the API containing the item's value. It is strongly recommended that you parameterize <i>every</i> variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: SQL injection"#, url: r#"https://portswigger.net/web-security/sql-injection"# },
            Reference { title: r#"Web Security Academy: Client-side SQL injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-sql-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/89.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-66: SQL Injection"#, url: r#"https://capec.mitre.org/data/definitions/66.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097969,
        declared_type_index: 2097969,
        name: r#"Client-side SQL injection (reflected DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>Client-side SQL injection arises when a script incorporates controllable  data into a client-side SQL query in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will execute an arbitrary SQL query within the local SQL database of the user's browser.</p>
<p>The potential impact of the vulnerability depends on the application's usage of the SQL database. If the database is used to store sensitive data (such as messages in a social networking application), then the attacker may be able to retrieve this data. If the database is used to store pending user actions (such as outgoing messages in an email application), then the attacker may be able to modify this data and carry out actions on the user's behalf.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based client-side SQL injection vulnerabilities is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. In the JavaScript executeSql() API, parameterized items can be designated within the query string using the query character (?), and for each parameterized item, an additional parameter is passed to the API containing the item's value. It is strongly recommended that you parameterize <i>every</i> variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: SQL injection"#, url: r#"https://portswigger.net/web-security/sql-injection"# },
            Reference { title: r#"Web Security Academy: Client-side SQL injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-sql-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/89.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-66: SQL Injection"#, url: r#"https://capec.mitre.org/data/definitions/66.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097970,
        declared_type_index: 2097970,
        name: r#"Client-side SQL injection (stored DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>Client-side SQL injection arises when a script incorporates controllable  data into a client-side SQL query in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will execute an arbitrary SQL query within the local SQL database of the user's browser.</p>
<p>The potential impact of the vulnerability depends on the application's usage of the SQL database. If the database is used to store sensitive data (such as messages in a social networking application), then the attacker may be able to retrieve this data. If the database is used to store pending user actions (such as outgoing messages in an email application), then the attacker may be able to modify this data and carry out actions on the user's behalf.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based client-side SQL injection vulnerabilities is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. In the JavaScript executeSql() API, parameterized items can be designated within the query string using the query character (?), and for each parameterized item, an additional parameter is passed to the API containing the item's value. It is strongly recommended that you parameterize <i>every</i> variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: SQL injection"#, url: r#"https://portswigger.net/web-security/sql-injection"# },
            Reference { title: r#"Web Security Academy: Client-side SQL injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-sql-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/89.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-66: SQL Injection"#, url: r#"https://capec.mitre.org/data/definitions/66.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097984,
        declared_type_index: 2097984,
        name: r#"WebSocket URL poisoning (DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>
<p>WebSocket URL poisoning occurs when a  script uses controllable  data as the target URL of a WebSocket connection. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to open a WebSocket connection to a URL that is under the attacker's control.</p>
<p>The potential impact of the vulnerability depends on the application's usage of WebSockets. If the application transmits sensitive data from the user's browser to the WebSocket server, then the attacker may be able to capture this data. If the application reads data from the WebSocket server and performs processing on this data, then the attacker may be able to subvert the application's logic or deliver additional client-side attacks against the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based WebSocket URL poisoning vulnerabilities is not to dynamically set the target URL of a WebSocket connection using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a target of a WebSocket. In general, this is best achieved by using a whitelist of URLs that are permitted WebSocket targets, and strictly validating the target against this list before creating the WebSocket. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: WebSocket URL poisoning (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/websocket-url-poisoning"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-345: Insufficient Verification of Data Authenticity"#, url: r#"https://cwe.mitre.org/data/definitions/345.html"# },
            Classification { title: r#"CWE-346: Origin Validation Error"#, url: r#"https://cwe.mitre.org/data/definitions/346.html"# },
            Classification { title: r#"CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')"#, url: r#"https://cwe.mitre.org/data/definitions/441.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097985,
        declared_type_index: 2097985,
        name: r#"WebSocket URL poisoning (reflected DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>WebSocket URL poisoning occurs when a  script uses controllable  data as the target URL of a WebSocket connection. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to open a WebSocket connection to a URL that is under the attacker's control.</p>
<p>The potential impact of the vulnerability depends on the application's usage of WebSockets. If the application transmits sensitive data from the user's browser to the WebSocket server, then the attacker may be able to capture this data. If the application reads data from the WebSocket server and performs processing on this data, then the attacker may be able to subvert the application's logic or deliver additional client-side attacks against the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based WebSocket URL poisoning vulnerabilities is not to dynamically set the target URL of a WebSocket connection using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a target of a WebSocket. In general, this is best achieved by using a whitelist of URLs that are permitted WebSocket targets, and strictly validating the target against this list before creating the WebSocket. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: WebSocket URL poisoning (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/websocket-url-poisoning"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-345: Insufficient Verification of Data Authenticity"#, url: r#"https://cwe.mitre.org/data/definitions/345.html"# },
            Classification { title: r#"CWE-346: Origin Validation Error"#, url: r#"https://cwe.mitre.org/data/definitions/346.html"# },
            Classification { title: r#"CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')"#, url: r#"https://cwe.mitre.org/data/definitions/441.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2097986,
        declared_type_index: 2097986,
        name: r#"WebSocket URL poisoning (stored DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>WebSocket URL poisoning occurs when a  script uses controllable  data as the target URL of a WebSocket connection. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to open a WebSocket connection to a URL that is under the attacker's control.</p>
<p>The potential impact of the vulnerability depends on the application's usage of WebSockets. If the application transmits sensitive data from the user's browser to the WebSocket server, then the attacker may be able to capture this data. If the application reads data from the WebSocket server and performs processing on this data, then the attacker may be able to subvert the application's logic or deliver additional client-side attacks against the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based WebSocket URL poisoning vulnerabilities is not to dynamically set the target URL of a WebSocket connection using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a target of a WebSocket. In general, this is best achieved by using a whitelist of URLs that are permitted WebSocket targets, and strictly validating the target against this list before creating the WebSocket. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: WebSocket URL poisoning (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/websocket-url-poisoning"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-345: Insufficient Verification of Data Authenticity"#, url: r#"https://cwe.mitre.org/data/definitions/345.html"# },
            Classification { title: r#"CWE-346: Origin Validation Error"#, url: r#"https://cwe.mitre.org/data/definitions/346.html"# },
            Classification { title: r#"CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')"#, url: r#"https://cwe.mitre.org/data/definitions/441.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098000,
        declared_type_index: 2098000,
        name: r#"Local file path manipulation (DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>

<p>Local file path manipulation  arises when a script uses controllable data as the filename parameter to a file handling API. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to open an arbitrary local file.</p>
<p>The potential impact of the vulnerability depends on the application's usage of the opened file. If the application reads data from the file, then the attacker may be able to retrieve this data. If the application writes data to the file, then the attacker may be able to write specific data to a sensitive file, such as an operating system configuration file. In both these cases, the actual exploitability of the potential vulnerability may depend on other suitable functionality being present in the application.</p>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based local file path manipulation vulnerabilities is not to dynamically pass a filename to a file handling API using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from accessing arbitrary files. In general, this is best achieved by using a whitelist of permitted filenames, and strictly validating the filename against this list before invoking the file handling API. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Local file path manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/local-file-path-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"#, url: r#"https://cwe.mitre.org/data/definitions/22.html"# },
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CAPEC-126: Path Traversal"#, url: r#"https://capec.mitre.org/data/definitions/126.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098001,
        declared_type_index: 2098001,
        name: r#"Local file path manipulation (reflected DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>Local file path manipulation  arises when a script uses controllable data as the filename parameter to a file handling API. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to open an arbitrary local file.</p>
<p>The potential impact of the vulnerability depends on the application's usage of the opened file. If the application reads data from the file, then the attacker may be able to retrieve this data. If the application writes data to the file, then the attacker may be able to write specific data to a sensitive file, such as an operating system configuration file. In both these cases, the actual exploitability of the potential vulnerability may depend on other suitable functionality being present in the application.</p>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based local file path manipulation vulnerabilities is not to dynamically pass a filename to a file handling API using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from accessing arbitrary files. In general, this is best achieved by using a whitelist of permitted filenames, and strictly validating the filename against this list before invoking the file handling API. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Local file path manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/local-file-path-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"#, url: r#"https://cwe.mitre.org/data/definitions/22.html"# },
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CAPEC-126: Path Traversal"#, url: r#"https://capec.mitre.org/data/definitions/126.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098002,
        declared_type_index: 2098002,
        name: r#"Local file path manipulation (stored DOM-based)"#,
        typical_severity: Severity::High,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>Local file path manipulation  arises when a script uses controllable data as the filename parameter to a file handling API. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to open an arbitrary local file.</p>
<p>The potential impact of the vulnerability depends on the application's usage of the opened file. If the application reads data from the file, then the attacker may be able to retrieve this data. If the application writes data to the file, then the attacker may be able to write specific data to a sensitive file, such as an operating system configuration file. In both these cases, the actual exploitability of the potential vulnerability may depend on other suitable functionality being present in the application.</p>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based local file path manipulation vulnerabilities is not to dynamically pass a filename to a file handling API using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from accessing arbitrary files. In general, this is best achieved by using a whitelist of permitted filenames, and strictly validating the filename against this list before invoking the file handling API. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Local file path manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/local-file-path-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"#, url: r#"https://cwe.mitre.org/data/definitions/22.html"# },
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CAPEC-126: Path Traversal"#, url: r#"https://capec.mitre.org/data/definitions/126.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098016,
        declared_type_index: 2098016,
        name: r#"Client-side XPath injection (DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>

<p>DOM-based XPath injection  arises when a script incorporates controllable data into an XPath query. An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause an arbitrary XPath query to execute, causing different data to be retrieved and processed by the application. Depending on the purpose for which the query results are used, it may be possible to subvert the application's logic, or cause unintended actions on behalf of the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based XPath injection vulnerabilities is not to incorporate into an XPath query any data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from modifying the XPath query in inappropriate ways. This may involve strict validation of specific items to ensure they do not contain any characters that may interfere with the structure of the query when it is parsed. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Client-side XPath injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-xpath-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-83: XPath Injection"#, url: r#"https://capec.mitre.org/data/definitions/83.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098017,
        declared_type_index: 2098017,
        name: r#"Client-side XPath injection (reflected DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>DOM-based XPath injection  arises when a script incorporates controllable data into an XPath query. An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause an arbitrary XPath query to execute, causing different data to be retrieved and processed by the application. Depending on the purpose for which the query results are used, it may be possible to subvert the application's logic, or cause unintended actions on behalf of the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based XPath injection vulnerabilities is not to incorporate into an XPath query any data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from modifying the XPath query in inappropriate ways. This may involve strict validation of specific items to ensure they do not contain any characters that may interfere with the structure of the query when it is parsed. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Client-side XPath injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-xpath-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-83: XPath Injection"#, url: r#"https://capec.mitre.org/data/definitions/83.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098018,
        declared_type_index: 2098018,
        name: r#"Client-side XPath injection (stored DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>DOM-based XPath injection  arises when a script incorporates controllable data into an XPath query. An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause an arbitrary XPath query to execute, causing different data to be retrieved and processed by the application. Depending on the purpose for which the query results are used, it may be possible to subvert the application's logic, or cause unintended actions on behalf of the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based XPath injection vulnerabilities is not to incorporate into an XPath query any data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from modifying the XPath query in inappropriate ways. This may involve strict validation of specific items to ensure they do not contain any characters that may interfere with the structure of the query when it is parsed. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Client-side XPath injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-xpath-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-83: XPath Injection"#, url: r#"https://capec.mitre.org/data/definitions/83.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098032,
        declared_type_index: 2098032,
        name: r#"Client-side JSON injection (DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>
<p>DOM-based JSON injection  arises when a script  incorporates controllable data into a string that is parsed as a JSON data structure and then processed by the application. An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause arbitrary JSON data to be processed. Depending on the purpose for which this data is used, it may be possible to subvert the application's logic, or cause unintended actions on behalf of the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based JSON injection vulnerabilities is not to parse as JSON any string containing data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from modifying the JSON structure in inappropriate ways. This may involve strict validation of specific items to ensure they do not contain any characters that may interfere with the structure of the JSON when it is parsed.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Client-side JSON injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-json-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098033,
        declared_type_index: 2098033,
        name: r#"Client-side JSON injection (reflected DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM-based JSON injection  arises when a script  incorporates controllable data into a string that is parsed as a JSON data structure and then processed by the application. An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause arbitrary JSON data to be processed. Depending on the purpose for which this data is used, it may be possible to subvert the application's logic, or cause unintended actions on behalf of the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based JSON injection vulnerabilities is not to parse as JSON any string containing data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from modifying the JSON structure in inappropriate ways. This may involve strict validation of specific items to ensure they do not contain any characters that may interfere with the structure of the JSON when it is parsed.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Client-side JSON injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-json-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098034,
        declared_type_index: 2098034,
        name: r#"Client-side JSON injection (stored DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM-based JSON injection  arises when a script  incorporates controllable data into a string that is parsed as a JSON data structure and then processed by the application. An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause arbitrary JSON data to be processed. Depending on the purpose for which this data is used, it may be possible to subvert the application's logic, or cause unintended actions on behalf of the user.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based JSON injection vulnerabilities is not to parse as JSON any string containing data that originated from an untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from modifying the JSON structure in inappropriate ways. This may involve strict validation of specific items to ensure they do not contain any characters that may interfere with the structure of the JSON when it is parsed.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Client-side JSON injection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/client-side-json-injection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098176,
        declared_type_index: 2098176,
        name: r#"Flash cross-domain policy"#,
        typical_severity: Severity::High,
        description: r#"<p>The Flash cross-domain policy controls whether Flash client components running on other domains can perform two-way interaction with the domain that publishes the policy. If another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially gain full access to the application within the security context of the logged in user.</p>
<p>Even if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by a third-party attacker to exploit the trust relationship and attack the application that allows access. Any domains that are allowed by the Flash cross-domain policy should be reviewed to determine whether it is appropriate for the application to fully trust both their intentions and security posture. </p>"#,
        remediation: Some(r#"<p>Any inappropriate entries in the Flash cross-domain policy file should be removed.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-942: Overly Permissive Cross-domain Whitelist"#, url: r#"https://cwe.mitre.org/data/definitions/942.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098432,
        declared_type_index: 2098432,
        name: r#"Silverlight cross-domain policy"#,
        typical_severity: Severity::High,
        description: r#"<p>The Silverlight cross-domain policy controls whether Silverlight client components running on other domains can perform two-way interaction with the domain that publishes the policy. If another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially gain full access to the application within the security context of the logged in user.</p>
<p>Even if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by a third-party attacker to exploit the trust relationship and attack the application that allows access. Any domains that are allowed by the Silverlight cross-domain policy should be reviewed to determine whether it is appropriate for the application to fully trust both their intentions and security posture. </p>"#,
        remediation: Some(r#"<p>Any inappropriate entries in the Silverlight cross-domain policy file should be removed.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-942: Overly Permissive Cross-domain Whitelist"#, url: r#"https://cwe.mitre.org/data/definitions/942.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098435,
        declared_type_index: 2098435,
        name: r#"Content security policy: allowlisted script resources"#,
        typical_severity: Severity::Info,
        description: r#"<p>Content Security Policy (CSP) is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviours such as untrusted JavaScript execution.
    Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.
</p>"#,
        remediation: Some(r#"<p>To prevent untrusted JavaScript execution, replace allowlisted resources in script-based directives with a secure, random nonce of at least 8 characters 'nonce-RANDOM'.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: What is CSP?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy"# },
            Reference { title: r#"Web Security Academy: What is XSS?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting#what-is-cross-site-scripting-xss"# },
            Reference { title: r#"Web Security Academy: Mitigating XSS attacks using CSP"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy#mitigating-xss-attacks-using-csp"# },
            Reference { title: r#"Web Security Academy: Preventing XSS"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/preventing"# },
            Reference { title: r#"Content Security Policy (CSP)"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)"#, url: r#"https://cwe.mitre.org/data/definitions/80.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-588: DOM-Based XSS"#, url: r#"https://capec.mitre.org/data/definitions/588.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098436,
        declared_type_index: 2098436,
        name: r#"Content security policy: allows untrusted script execution"#,
        typical_severity: Severity::Info,
        description: r#"<p>Content Security Policy (CSP) is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviours such as untrusted JavaScript execution.
    Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.
</p>"#,
        remediation: Some(r#"<p>
    Mitigate cross-site scripting by avoiding 'unsafe-inline', 'unsafe-eval', data: URLs, and global wildcards in script directives. Use a secure, random
    nonce of at least 8 characters 'nonce-RANDOM' to prevent untrusted JavaScript execution.
</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: What is CSP?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy"# },
            Reference { title: r#"Web Security Academy: What is XSS?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting#what-is-cross-site-scripting-xss"# },
            Reference { title: r#"Web Security Academy: Mitigating XSS attacks using CSP"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy#mitigating-xss-attacks-using-csp"# },
            Reference { title: r#"Web Security Academy: Preventing XSS"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/preventing"# },
            Reference { title: r#"Content Security Policy (CSP)"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"#, url: r#"https://cwe.mitre.org/data/definitions/79.html"# },
            Classification { title: r#"CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)"#, url: r#"https://cwe.mitre.org/data/definitions/80.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-588: DOM-Based XSS"#, url: r#"https://capec.mitre.org/data/definitions/588.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098437,
        declared_type_index: 2098437,
        name: r#"Content security policy: allows untrusted style execution"#,
        typical_severity: Severity::Info,
        description: r#"<p>Content Security Policy (CSP) is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviours such as untrusted JavaScript execution.
    Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.
</p>"#,
        remediation: Some(r#"<p>
    Mitigate style-based data exfiltration by avoiding 'unsafe-inline', data: URLs, and global wildcards in style directives.
    Use a secure, random nonce of at least 8 characters 'nonce-RANDOM' in the relevant directive.
</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: What is CSP?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy"# },
            Reference { title: r#"PortSwigger Research: Blind CSS exfiltration"#, url: r#"https://portswigger.net/research/blind-css-exfiltration"# },
            Reference { title: r#"PortSwigger Research: Offensive CSS research"#, url: r#"https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities#badcss"# },
            Reference { title: r#"Content Security Policy (CSP)"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-468: Generic Cross-Browser Cross-Domain Theft"#, url: r#"https://capec.mitre.org/data/definitions/468.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098438,
        declared_type_index: 2098438,
        name: r#"Content security policy: malformed syntax"#,
        typical_severity: Severity::Info,
        description: r#"<p>Content Security Policy (CSP) is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviours such as untrusted JavaScript execution.
    Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.
</p>"#,
        remediation: Some(r#"<p>Using malformed syntax in your policy causes the browser to ignore the directive. Ensure that you use the correct syntax in your policy.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: What is CSP?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy"# },
            Reference { title: r#"Content Security Policy (CSP)"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"# },
        ],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 2098439,
        declared_type_index: 2098439,
        name: r#"Content security policy: allows clickjacking"#,
        typical_severity: Severity::Info,
        description: r#"<p>
    Content Security Policy (CSP) is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviours such as untrusted JavaScript execution.
    Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.
</p>"#,
        remediation: Some(r#"<p>
    We recommend that you set the frame-ancestors directive to 'none' if you do not want your site to be framed, or 'self' if you want to allow it to frame itself. In addition,
    use the X-Frame-Options header with DENY or SAMEORIGIN, based on your needs.
</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Clickjacking"#, url: r#"https://portswigger.net/web-security/clickjacking"# },
            Reference { title: r#"X-Frame-Options"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"# },
            Reference { title: r#"Web Security Academy: What is CSP?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy"# },
            Reference { title: r#"Web Security Academy: Protecting against clickjacking using CSP"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy#protecting-against-clickjacking-using-csp"# },
            Reference { title: r#"Content Security Policy (CSP)"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-693: Protection Mechanism Failure"#, url: r#"https://cwe.mitre.org/data/definitions/693.html"# },
            Classification { title: r#"CWE-1021: Improper Restriction of Rendered UI Layers or Frames"#, url: r#"https://cwe.mitre.org/data/definitions/1021.html"# },
            Classification { title: r#"CAPEC-103: Clickjacking"#, url: r#"https://capec.mitre.org/data/definitions/103.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098440,
        declared_type_index: 2098440,
        name: r#"Content security policy: allows form hijacking"#,
        typical_severity: Severity::Info,
        description: r#"<p>Content Security Policy (CSP) is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviours such as untrusted JavaScript execution.
    Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.
</p>"#,
        remediation: Some(r#"<p>We recommend using the form-action directive in the CSP response header to control form post destinations. If no form actions are used, set form-action to 'none' to block
    untrusted forms. For applications without external form URLs, use 'self' to allow only same-origin URLs. If needed, allow list hosts for external URL form submissions, but
    be aware this lets attackers submit to these external resources.
</p>"#),
        references: &[
            Reference { title: r#"PortSwigger Research: Stealing passwords from infosec Mastodon - without bypassing CSP"#, url: r#"https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp"# },
            Reference { title: r#"Web Security Academy: What is CSP?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy"# },
            Reference { title: r#"Content Security Policy (CSP)"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098441,
        declared_type_index: 2098441,
        name: r#"Content security policy: not enforced"#,
        typical_severity: Severity::Info,
        description: r#"<p>Content Security Policy (CSP) is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviours such as untrusted JavaScript execution.
    Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.
</p>"#,
        remediation: Some(r#"<p>We recommend transitioning from using the Content-Security-Policy-Report-Only header to the Content-Security-Policy header for CSP deployment, ensuring effective policy enforcement.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: What is CSP?"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/content-security-policy"# },
            Reference { title: r#"Content Security Policy (CSP)"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"# },
        ],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 2098448,
        declared_type_index: 2098448,
        name: r#"GraphQL endpoint found"#,
        typical_severity: Severity::Info,
        description: r#"<p>Unlike REST APIs, GraphQL servers operate on a single endpoint. All messages are sent to this endpoint, with the body of the message determining how the server handles the request.</p>
<p>A publicly-available endpoint does not necessarily present a security vulnerability in and of itself. However, this information can still be valuable to attackers, as by definition any attacks on the GraphQL server will use the endpoint discovered. For example, an attacker could then attempt to run an introspection query against the endpoint, which could reveal the entire GraphQL schema if successful.</p>"#,
        remediation: Some(r#"<p>Ensure that you have disabled introspection on your GraphQL server when deploying to production. This will prevent attackers from using introspection queries to discover more about the operations available in your API, and other potentially sensitive information such as field descriptions.</p>
<p>Also, ensure that your GraphQL endpoint is only available over the POST HTTP method. Having your API available over methods such as GET or OPTIONS presents an additional attack surface and can leave the endpoint open to vulnerabilities such as CSRF.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: GraphQL API vulnerabilities"#, url: r#"https://portswigger.net/web-security/graphql"# },
        ],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 2098449,
        declared_type_index: 2098449,
        name: r#"GraphQL endpoint discovered"#,
        typical_severity: Severity::Info,
        description: r#"<p>Unlike REST APIs, GraphQL servers operate on a single endpoint. All messages are sent to this endpoint, with the body of the message determining how the server handles the request.</p>
<p>A publicly-available endpoint does not necessarily present a security vulnerability in and of itself. However, this information can still be valuable to attackers, as by definition any attacks on the GraphQL server will use the endpoint discovered. For example, an attacker could then attempt to run an introspection query against the endpoint, which could reveal the entire GraphQL schema if successful.</p>"#,
        remediation: Some(r#"<p>Ensure that you have disabled introspection on your GraphQL server when deploying to production. This will prevent attackers from using introspection queries to discover more about the operations available in your API, and other potentially sensitive information such as field descriptions.</p>
<p>Also, ensure that your GraphQL endpoint is only available over the POST HTTP method. Having your API available over methods such as GET or OPTIONS presents an additional attack surface and can leave the endpoint open to vulnerabilities such as CSRF.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: GraphQL API vulnerabilities"#, url: r#"https://portswigger.net/web-security/graphql"# },
        ],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 2098450,
        declared_type_index: 2098450,
        name: r#"GraphQL introspection enabled"#,
        typical_severity: Severity::Low,
        description: r#"<p>Introspection uses built-in queries to return information on a GraphQL schema itself. Like regular GraphQL queries, introspection queries are highly customizable, enabling users to specify the content and data shape of the response.</p>
<p>GraphQL introspection can represent a significant security risk when enabled in production, as it enables attackers to see what operations are available to them within the API, as well as other potentially sensitive information such as type descriptions and private fields.</p>"#,
        remediation: Some(r#"<p>Ensure that you have disabled introspection on your GraphQL server. Consult your server documentation if you are unsure how to do this.</p>"#),
        references: &[
            Reference { title: r#"GraphQL Introspection"#, url: r#"https://graphql.org/learn/introspection/"# },
            Reference { title: r#"Web Security Academy: GraphQL API vulnerabilities"#, url: r#"https://portswigger.net/web-security/graphql"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098451,
        declared_type_index: 2098451,
        name: r#"GraphQL suggestions enabled"#,
        typical_severity: Severity::Low,
        description: r#"<p>GraphQL suggestions are an Apollo feature in which the server is configured to respond to invalid queries with suggestions for valid queries that have a similar syntax.</p>
<p>Suggestions can represent a significant security risk, as they enable attackers to glean information about a GraphQL schema even if introspection is disabled. By sending intentionally invalid queries and collating suggestions in responses, attackers can learn the names and structures of valid queries and mutations.</p>"#,
        remediation: Some(r#"<p>Ensure that you have disabled or otherwise masked error messages containing suggestions on your GraphQL server.</p>"#),
        references: &[
            Reference { title: r#"Disabling Apollo suggestions"#, url: r#"https://github.com/apollographql/apollo-server/issues/3919"# },
            Reference { title: r#"Clairvoyance: A tool to gather information from suggestions"#, url: r#"https://github.com/nikitastupin/clairvoyance"# },
            Reference { title: r#"Web Security Academy: GraphQL API vulnerabilities"#, url: r#"https://portswigger.net/web-security/graphql"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098452,
        declared_type_index: 2098452,
        name: r#"GraphQL content type not validated"#,
        typical_severity: Severity::Low,
        description: r#"<p>Cross-site request forgery (CSRF) vulnerabilities enable an attacker to induce users to perform actions that they do not intend to perform. This is done by creating a malicious website that forges a cross-domain request to the vulnerable application.</p>
<p>Cross-site request forgery (CSRF) vulnerabilities in a GraphQL endpoint can arise when the content type is not validated. POST requests using a content-type of application/json are secure against forgery as long as the content type is validated, as an attacker wouldn't be able to make the victim's browser send this request.</p>
<p>However, alternative methods such as GET, or any request that has a content-type of x-www-form-urlencoded, can be sent by a browser and so may leave users vulnerable to attack. Where this is the case, attackers may be able to craft exploits that use a valid CSRF token from a previous request to send malicious requests to the API.</p>"#,
        remediation: Some(r#"<p>Ensure that your GraphQL endpoint validates the content type. If the content type cannot be validated, ensure a valid CSRF token is required.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: GraphQL API vulnerabilities"#, url: r#"https://portswigger.net/web-security/graphql"# },
            Reference { title: r#"Web Security Academy: Cross-site request forgery"#, url: r#"https://portswigger.net/web-security/csrf"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-352: Cross-Site Request Forgery"#, url: r#"https://cwe.mitre.org/data/definitions/352.html"# },
            Classification { title: r#"CAPEC-62: Cross-Site Request Forgery"#, url: r#"https://capec.mitre.org/data/definitions/62.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098688,
        declared_type_index: 2098688,
        name: r#"Cross-origin resource sharing"#,
        typical_severity: Severity::Info,
        description: r#"<p>An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.</p><p>If another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially retrieve content from the application, and sometimes carry out actions within the security context of the logged in user.</p>
<p>Even if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by an attacker to exploit the trust relationship and attack the application that allows access. CORS policies on pages containing sensitive information should be reviewed to determine whether it is appropriate for the application to trust both the intentions and security posture of any domains granted access.</p>"#,
        remediation: Some(r#"<p>Any inappropriate domains should be removed from the CORS policy.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-origin resource sharing (CORS)"#, url: r#"https://portswigger.net/web-security/cors"# },
            Reference { title: r#"Exploiting CORS Misconfigurations"#, url: r#"https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-942: Overly Permissive Cross-domain Whitelist"#, url: r#"https://cwe.mitre.org/data/definitions/942.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098689,
        declared_type_index: 2098689,
        name: r#"Cross-origin resource sharing: arbitrary origin trusted"#,
        typical_severity: Severity::High,
        description: r#"<p>An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.</p><p>
Trusting arbitrary origins effectively disables the same-origin policy, allowing two-way interaction by third-party web sites. Unless the response consists only of unprotected public content, this policy is likely to present a security risk.</p>
<p>If the site  specifies the header Access-Control-Allow-Credentials: true, third-party sites may be able to carry out privileged actions and retrieve sensitive information. Even if it does not, attackers may be able to  bypass any IP-based access controls by proxying through users'  browsers.</p>"#,
        remediation: Some(r#"<p>Rather than using a wildcard or programmatically verifying supplied origins, use a whitelist of trusted domains.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-origin resource sharing (CORS)"#, url: r#"https://portswigger.net/web-security/cors"# },
            Reference { title: r#"Exploiting CORS Misconfigurations"#, url: r#"https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-942: Overly Permissive Cross-domain Whitelist"#, url: r#"https://cwe.mitre.org/data/definitions/942.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098690,
        declared_type_index: 2098690,
        name: r#"Cross-origin resource sharing: unencrypted origin trusted"#,
        typical_severity: Severity::Low,
        description: r#"<p>An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.</p>
<p>If a site allows interaction from an origin that uses unencrypted HTTP communications, then it is vulnerable to an attacker who is in a position to view and modify a user's unencrypted network traffic. The attacker can control the responses from unencrypted origins, thereby injecting content that is able to interact with the application that publishes the policy. This means that the application is effectively extending trust to all such attackers, thereby undoing much of the benefit of using HTTPS communications. </p>"#,
        remediation: Some(r#"<p>Only trust origins that use encrypted HTTPS communications.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-origin resource sharing (CORS)"#, url: r#"https://portswigger.net/web-security/cors"# },
            Reference { title: r#"Exploiting CORS Misconfigurations"#, url: r#"https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-942: Overly Permissive Cross-domain Whitelist"#, url: r#"https://cwe.mitre.org/data/definitions/942.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098691,
        declared_type_index: 2098691,
        name: r#"Cross-origin resource sharing: all subdomains trusted"#,
        typical_severity: Severity::Low,
        description: r#"<p>An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.</p>
<p>If an application allows interaction from all subdomains, then this significantly increases its attack surface. For example, a cross-site scripting (XSS) vulnerability in any subdomain could potentially compromise the application that publishes the policy. Some consumer ISPs return custom content when requests are made to unregistered subdomains, which can introduce XSS vulnerabilities even if all of an organization's own applications are secure.</p>"#,
        remediation: Some(r#"<p>Rather than trusting all subdomains,  use a whitelisted of trusted subdomains.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-origin resource sharing (CORS)"#, url: r#"https://portswigger.net/web-security/cors"# },
            Reference { title: r#"Exploiting CORS Misconfigurations"#, url: r#"https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-942: Overly Permissive Cross-domain Whitelist"#, url: r#"https://cwe.mitre.org/data/definitions/942.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2098768,
        declared_type_index: 2098768,
        name: r#"Web cache deception"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Web cache deception exploits discrepancies between cache proxy and backend parsers, leading web servers to mistakenly cache and serve dynamic content as though it were static.
This vulnerability is often exploited by attackers adding fake static file extensions to dynamic URLs, for example, changing "/path" to "/path/WCD.css".
When users click on these modified links, the caching system erroneously identifies the request as for a static resource and caches the response, making the user's sensitive information public.
If subsequent unauthorized users make a request to the same URL then they will be served the cached page, potentially exposing the sensitive information repeatedly.
The distributed nature of web caches means that even a single web cache deception attack can have far-reaching effects, extending the potential for sensitive data exposure across various users and sessions.</p>"#,
        remediation: Some(r#"<p>To mitigate the risk of web cache deception vulnerabilities, web administrators should:</p>
<ul>
    <li>Clearly specify which content should be cached. This involves setting up clear caching rules within your application.</li>
    <li>Implement strong cache management by using Cache-Control headers. For dynamic content, use settings like no-cache to prevent it from being stored.</li>
    <li>Implement strong URL parameters validation, blocking any unexpected file extensions or paths that could be exploited.</li>
    <li>Regularly review your cache configuration and audit the content it contains. This can help you identify and address any potential issues quickly.</li>
    <li>Treat all content as non-cacheable unless it has been explicitly approved for caching. This approach helps minimize the risk of inadvertently caching sensitive information.</li>
</ul>"#),
        references: &[],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 2098944,
        declared_type_index: 2098944,
        name: r#"Cross-site request forgery"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Cross-site request forgery (CSRF) vulnerabilities may arise when applications rely solely on HTTP cookies to identify the user that has issued a particular request. Because browsers automatically add cookies to requests regardless of their origin, it may be possible for an attacker to create a malicious web site that forges a cross-domain request to the vulnerable application. For a request to be vulnerable to CSRF, the following conditions must hold:</p>
<ul>
<li>The request can be issued cross-domain, for example using an HTML form. If the request contains non-standard headers or body content, then it may only be issuable from a page that originated on the same domain.</li>
<li>The application relies solely on HTTP cookies or Basic Authentication to identify the user that issued the request. If the application places session-related tokens elsewhere within the request, then it may not be vulnerable.</li>
<li>The request performs some privileged action within the application, which modifies the application's state based on the identity of the issuing user.</li><li>The attacker can determine all the parameters required to construct a request that performs the action. If the request contains any values that the attacker cannot determine or predict, then it is not vulnerable.</li></ul>"#,
        remediation: Some(r#"<p>The most effective way to protect against CSRF vulnerabilities is to include within relevant requests an additional token that is not transmitted in a cookie: for example, a parameter in a hidden form field. This additional token should contain sufficient entropy, and be generated using a cryptographic random number generator, such that it is not feasible for an attacker to determine or predict the value of any token that was issued to another user. The token should be associated with the user's session, and the application should validate that the correct token is received before performing any action resulting from the request.</p>
<p>An alternative approach, which may be easier to implement, is to validate that Host and Referer headers in relevant requests are both present and contain the same domain name. However, this approach is somewhat less robust: historically, quirks in browsers and plugins have often enabled attackers to forge cross-domain requests that manipulate these headers to bypass such defenses. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site request forgery"#, url: r#"https://portswigger.net/web-security/csrf"# },
            Reference { title: r#"Using Burp to Test for Cross-Site Request Forgery"#, url: r#"https://support.portswigger.net/customer/portal/articles/1965674-using-burp-to-test-for-cross-site-request-forgery-csrf-"# },
            Reference { title: r#"The Deputies Are Still Confused"#, url: r#"https://media.blackhat.com/eu-13/briefings/Lundeen/bh-eu-13-deputies-still-confused-lundeen-wp.pdf"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-352: Cross-Site Request Forgery (CSRF)"#, url: r#"https://cwe.mitre.org/data/definitions/352.html"# },
            Classification { title: r#"CAPEC-62: Cross Site Request Forgery"#, url: r#"https://capec.mitre.org/data/definitions/62.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2099200,
        declared_type_index: 2099200,
        name: r#"SMTP header injection"#,
        typical_severity: Severity::Medium,
        description: r#"<p>SMTP header injection vulnerabilities arise when user input is placed into email headers without adequate sanitization, allowing an attacker to inject additional headers with arbitrary values. This behavior can be exploited to send copies of emails to third parties, attach viruses, deliver phishing attacks, and often alter the content of emails. It is typically exploited by spammers looking to leverage the vulnerable company's reputation to add legitimacy to their emails.
</p>
<p>
This issue is particularly serious if the email contains sensitive information not intended for the attacker, such as a password reset token.
</p>"#,
        remediation: Some(r#"<p>Validate that user input conforms to a whitelist of safe characters before placing it into email headers. In particular, input containing newlines and carriage returns should be rejected.
Alternatively, consider switching to an email library that automatically prevents such attacks.
</p>"#),
        references: &[
            Reference { title: r#"Burp Collaborator"#, url: r#"https://portswigger.net/blog/introducing-burp-collaborator"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')"#, url: r#"https://cwe.mitre.org/data/definitions/93.html"# },
            Classification { title: r#"CWE-159: Failure to Sanitize Special Element"#, url: r#"https://cwe.mitre.org/data/definitions/159.html"# },
            Classification { title: r#"CAPEC-183: IMAP/SMTP Command Injection"#, url: r#"https://capec.mitre.org/data/definitions/183.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2099456,
        declared_type_index: 2099456,
        name: r#"JWT signature not verified"#,
        typical_severity: Severity::High,
        description: r#"<p>
  The JSON Web Token specification provides several ways for developers to digitally sign payload claims.
  This ensures data integrity and robust user authentication. However, some servers fail to properly verify the signature,
  which can result in them accepting tokens with invalid signatures.
</p>
<p>
  A malicious user can exploit this vulnerability by supplying an arbitrary claim in the JWT payload to obtain new privileges or impersonate other users.
  For example, if the token contains a "username": "joe" claim, an attacker could potentially change this to  "username": "admin" to grant themselves higher privileges.
</p>
<p>
  Burp Suite detects this vulnerability by comparing responses to multiple requests with proper and improper signatures.
  Although this is a reliable detection method, it is not bulletproof. When this issue is reported, we recommend manually checking that the difference in responses was
  indeed caused by the different JWT permutations.
</p>"#,
        remediation: Some(r#"<p>
  Ensure that the signature of the JWT is properly verified for all supported algorithms.
</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-345: Insufficient Verification of Data Authenticity"#, url: r#"https://cwe.mitre.org/data/definitions/345.html"# },
            Classification { title: r#"CWE-347: Improper Verification of Cryptographic Signature"#, url: r#"https://cwe.mitre.org/data/definitions/347.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2099457,
        declared_type_index: 2099457,
        name: r#"JWT none algorithm supported"#,
        typical_severity: Severity::High,
        description: r#"<p>
  All JSON Web Tokens should contain the "alg" header parameter, which specifies the algorithm that the server should use to verify the signature of the token.
  In addition to cryptographically strong algorithms, the JWT specification also defines the "none" algorithm, which can be used with "unsecured" (unsigned) JWTs.
  When this algorithm is supported on the server, it may accept tokens that have no signature at all.
</p>

<p>
  As the JWT header can be tampered with client-side, a malicious user could change the "alg" header to "none", then remove the signature and check whether the server
  still accepts the token.
</p>

<p>
  If it does, they could exploit this vulnerability by supplying an arbitrary claim in the JWT payload to escalate their privileges or impersonate other users.
  For example, if the token contains a "username": "joe" claim, they could change this to  "username": "admin".
</p>"#,
        remediation: Some(r#"<p>
  Ensure that unsecured JWTs are rejected by the server and only cryptographically strong algorithms are accepted and verified.
  Even if the application does not directly use unsecured JWTs, it's important to make sure that the "alg": "none" header parameter is
  restricted by the underlying JWT parsing library.
</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-345: Insufficient Verification of Data Authenticity"#, url: r#"https://cwe.mitre.org/data/definitions/345.html"# },
        ],
    },
    IssueDefinition {
        type_index: 2099458,
        declared_type_index: 2099458,
        name: r#"JWT self-signed JWK header supported"#,
        typical_severity: Severity::High,
        description: r#"<p>
  The JSON Web Signature specification defines the optional "jwk" header, which contains information about the key used to digitally sign the JWT.
  This parameter is particularly useful for servers that are configured to use multiple different keys because it can help to determine which key to
  use when verifying the signature.
</p>

<p>
  If the target application implicitly trusts this header, it may verify the signature using an arbitrary public key provided in this way,
  essentially relying on data that can be tampered with client-side.
</p>

<p>
  A malicious user could insert or modify a "jwk" header so that it contains an RSA public key that they've generated themselves.
  They could then re-sign the token using the matching private key and check whether the server still accepts it.
</p>

<p>
  If it does, they could exploit this vulnerability by supplying an arbitrary claim in the JWT payload to escalate their privileges
  or impersonate other users. For example, if the token contains a "username": "joe" claim, they could change this to  "username": "admin".
</p>"#,
        remediation: Some(r#"<p>
  Configure the server so that it does not implicitly trust the "jwk" header parameter.
  If this is present, the server should verify it against the whitelist of trusted values if possible.
</p>

<p>
  We recommend that you only use verification keys obtained from trusted sources, rather than from data that can be modified client-side.
  Even if the application does not directly use the "jwk" header, it's important to make sure that it is restricted by the underlying JWT parsing library.
</p>"#),
        references: &[],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 2099459,
        declared_type_index: 2099459,
        name: r#"JWT weak HMAC secret"#,
        typical_severity: Severity::High,
        description: r#"<p>
  The JSON Web Token specification provides several ways for developers to digitally sign payload claims.
  This ensures data integrity and robust user authentication.
  Whenever developers use HMAC signatures, they need to provide a secret key, which is used for both signing and verifying tokens.
  If this secret is not strong enough, the whole signature can be compromised.
</p>

<p>
  For every JWT observed in your traffic, Burp Suite attempts to brute-force the signature using a list of common weak secrets.
  This process is performed offline, without sending any requests to the server.
</p>

<p>
  If the secret can be brute-forced this way, a malicious user can modify the JWT header and payload, then re-sign the token with a valid signature for the server.
  They could then exploit this vulnerability by supplying an arbitrary claim in the JWT payload to escalate their privileges or impersonate other users.
  For example, if the token contains a "username": "joe" claim, they could change this to  "username": "admin".
</p>"#,
        remediation: Some(r#"<p>
  Ensure that a strong, unpredictable secret is used for calculating the HMAC signature on the server. We recommend using a randomly generated value at least 32 bytes in length.
</p>"#),
        references: &[],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 2099460,
        declared_type_index: 2099460,
        name: r#"JWT arbitrary jku header supported"#,
        typical_severity: Severity::High,
        description: r#"<p>
  The JSON Web Signature specification defines the optional "jku" header, which contains a URL pointing to a set of keys used by the server to digitally sign the JWT.
  This parameter is particularly useful for servers that are configured to use multiple different keys because it can help to determine which key to use when verifying the signature.
</p>

<p>
  If the target application implicitly trusts this header, it may verify the signature using an arbitrary public key obtained from the provided URL,
  essentially relying on data that can be tampered with client-side.
</p>

<p>
  A malicious user could insert or modify a "jku" header so that it points to an external server containing a JSON Web Key Set that they've generated themselves.
  They could then re-sign the token using the matching private key and check whether the server still accepts it.
</p>

<p>
  If it does, they could exploit this vulnerability by supplying an arbitrary claim in the JWT payload to escalate their privileges or impersonate other users.
  For example, if the token contains a "username": "joe" claim, they could change this to  "username": "admin".
</p>"#,
        remediation: Some(r#"<p>
  Configure the server so that it does not implicitly trust the "jku" header parameter.
  If this is present, the server should verify it against the whitelist of trusted values if possible.
</p>

<p>
  We recommend that you only use verification keys obtained from trusted sources, rather than from data that can be modified client-side.
  Even if the application does not directly use the "jku" header, it's important to make sure that it is restricted by the underlying JWT parsing library.
</p>"#),
        references: &[],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 2099461,
        declared_type_index: 2099461,
        name: r#"JWT arbitrary x5u header supported"#,
        typical_severity: Severity::High,
        description: r#"<p>
  The JSON Web Signature specification defines the optional "x5u" header, which contains a URL pointing to the X.509 public key certificate or certificate chain for
  the key used to digitally sign the JWT. This parameter is particularly useful for servers that are configured to use multiple different keys because it can help to
  determine which key to use when verifying the signature.
</p>

<p>
  If the target application trusts this header, it may verify the signature using an arbitrary public key obtained from the provided URL,
  essentially relying on data that can be controlled by a third party.
</p>

<p>
  A malicious user could insert or modify an "x5u" header so that it points to an external server containing a public key certificate that they've generated themselves.
  They could then re-sign the token using the matching private key certificate and check whether the server still accepts it.
</p>

<p>
  If it does, they could exploit this vulnerability by supplying an arbitrary claim in the JWT payload to escalate their privileges or impersonate other users.
  For example, if the token contains a "username": "joe" claim, they could change this to  "username": "admin".
</p>"#,
        remediation: Some(r#"<p>
  Configure the server so that it does not implicitly trust the "x5u" header parameter.
  If this is present, the server should verify it against the whitelist of trusted values if possible.
</p>

<p>
  We recommend that you only use verification keys obtained from trusted sources, rather than from data that can be modified client-side.
  Even if the application does not directly use the "x5u" header, it's important to make sure that it is restricted by the underlying JWT parsing library.
</p>"#),
        references: &[],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 3145984,
        declared_type_index: 3145984,
        name: r#"Cleartext submission of password"#,
        typical_severity: Severity::High,
        description: r#"<p>Some applications transmit passwords over unencrypted connections, making them vulnerable to interception. To exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.</p>
<p>Vulnerabilities that result in the disclosure of users' passwords can result in compromises that are extremely difficult to investigate due to obscured audit trails. Even if the application itself only handles non-sensitive information, exposing passwords puts users who have re-used their password elsewhere at risk.</p>"#,
        remediation: Some(r#"<p>Applications should use transport-level encryption (SSL or TLS) to protect all sensitive communications passing between the client and the server. Communications that should be protected include the login mechanism and related functionality, and any functions where sensitive data can be accessed or privileged actions can be performed. These areas should employ their own session handling mechanism, and the session tokens used should never be transmitted over unencrypted communications. If HTTP cookies are used for transmitting session tokens, then the secure flag should be set to prevent transmission over clear-text HTTP.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-319: Cleartext Transmission of Sensitive Information"#, url: r#"https://cwe.mitre.org/data/definitions/319.html"# },
            Classification { title: r#"CAPEC-117: Interception"#, url: r#"https://capec.mitre.org/data/definitions/117.html"# },
        ],
    },
    IssueDefinition {
        type_index: 3146240,
        declared_type_index: 3146240,
        name: r#"External service interaction (DNS)"#,
        typical_severity: Severity::Info,
        description: r#"<p>The ability to induce an application to interact with an arbitrary external service, such as a web or mail server, does not constitute a vulnerability in its own right. This might even be the intended behavior of the application. However, in some cases, it can indicate a vulnerability with serious consequences.</p>
<p>If you can trigger DNS-based interactions, it is normally possible to trigger interactions using other service types. Burp Scanner reports these as separate issues. You may find that a payload, such as a URL, only triggers a DNS-based interaction, even though you were expecting interactions with a different service as well. This could be due to egress filters on the network layer that prevent the application from connecting to these other services. However, some systems perform DNS lookups without any intention of connecting to the remote host. This behavior is typically harmless.</p>
<p>The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy. By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers.</p>"#,
        remediation: Some(r#"<p>You should review the purpose and intended use of the relevant application functionality, 
  and determine whether the ability to trigger arbitrary external service interactions is intended behavior. 
  If so, you should be aware of the types of attacks that can be performed via this behavior and take appropriate measures. 
  These measures might include blocking network access from the application server to other internal systems, and hardening the application server itself to remove any services available on the local loopback adapter.</p>
<p>If the ability to trigger arbitrary external service interactions is not intended behavior, then you should implement a whitelist of permitted services and hosts, and block any interactions that do not appear on this whitelist.</p>

<p>Out-of-Band Application Security Testing (OAST) is highly effective at uncovering high-risk features, to the point where finding the root cause of an interaction can be quite challenging. To find the source of an external service interaction, try to identify whether it is triggered by specific application functionality, or occurs indiscriminately on all requests. If it occurs on all endpoints, a front-end CDN or application firewall may be responsible, or a back-end analytics system parsing server logs. In some cases, interactions may originate from third-party systems; for example, a HTTP request may trigger a poisoned email which passes through a link-scanner on its way to the recipient.</p>"#),
        references: &[
            Reference { title: r#"Burp Collaborator"#, url: r#"https://portswigger.net/blog/introducing-burp-collaborator"# },
            Reference { title: r#"Out-of-band application security testing (OAST)"#, url: r#"https://portswigger.net/burp/application-security-testing/oast"# },
            Reference { title: r#"PortSwigger Research: Cracking the Lens"#, url: r#"https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-918: Server-Side Request Forgery (SSRF)"#, url: r#"https://cwe.mitre.org/data/definitions/918.html"# },
            Classification { title: r#"CWE-406: Insufficient Control of Network Message Volume (Network Amplification)"#, url: r#"https://cwe.mitre.org/data/definitions/406.html"# },
        ],
    },
    IssueDefinition {
        type_index: 3146256,
        declared_type_index: 3146256,
        name: r#"External service interaction (HTTP)"#,
        typical_severity: Severity::High,
        description: r#"<p>External service interaction arises when it is possible to induce an application to interact with an arbitrary external service, such as a web or mail server. The ability to trigger arbitrary external service interactions does not constitute a vulnerability in its own right, and in some cases might even be the intended behavior of the application.
However, in many cases, it can indicate a vulnerability with serious consequences.</p>
<p>The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy.
  By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. 
  This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. 
  Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers. </p>"#,
        remediation: Some(r#"<p>You should review the purpose and intended use of the relevant application functionality, 
  and determine whether the ability to trigger arbitrary external service interactions is intended behavior. 
  If so, you should be aware of the types of attacks that can be performed via this behavior and take appropriate measures. 
  These measures might include blocking network access from the application server to other internal systems, and hardening the application server itself to remove any services available on the local loopback adapter.</p>
<p>If the ability to trigger arbitrary external service interactions is not intended behavior, then you should implement a whitelist of permitted services and hosts, and block any interactions that do not appear on this whitelist.</p>

<p>Out-of-Band Application Security Testing (OAST) is highly effective at uncovering high-risk features, to the point where finding the root cause of an interaction can be quite challenging. To find the source of an external service interaction, try to identify whether it is triggered by specific application functionality, or occurs indiscriminately on all requests. If it occurs on all endpoints, a front-end CDN or application firewall may be responsible, or a back-end analytics system parsing server logs. In some cases, interactions may originate from third-party systems; for example, a HTTP request may trigger a poisoned email which passes through a link-scanner on its way to the recipient.</p>"#),
        references: &[
            Reference { title: r#"Burp Collaborator"#, url: r#"https://portswigger.net/blog/introducing-burp-collaborator"# },
            Reference { title: r#"Out-of-band application security testing (OAST)"#, url: r#"https://portswigger.net/burp/application-security-testing/oast"# },
            Reference { title: r#"PortSwigger Research: Cracking the Lens"#, url: r#"https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-918: Server-Side Request Forgery (SSRF)"#, url: r#"https://cwe.mitre.org/data/definitions/918.html"# },
            Classification { title: r#"CWE-406: Insufficient Control of Network Message Volume (Network Amplification)"#, url: r#"https://cwe.mitre.org/data/definitions/406.html"# },
        ],
    },
    IssueDefinition {
        type_index: 3146272,
        declared_type_index: 3146272,
        name: r#"External service interaction (SMTP)"#,
        typical_severity: Severity::Info,
        description: r#"<p>External service interaction arises when it is possible to induce an application to interact with an arbitrary external service, such as a web or mail server. The ability to trigger arbitrary external service interactions does not constitute a vulnerability in its own right, and in some cases might even be the intended behavior of the application.
However, in many cases, it can indicate a vulnerability with serious consequences.</p>
<p>The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy.
  By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. 
  This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. 
  Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers. </p>
<p>The facility to generate an email to an arbitrary address is often intended application behavior. But this is not necessarily the case, particulary in cases where the destination address is not explicitly entered on-screen by the user.</p>"#,
        remediation: Some(r#"<p>You should review the purpose and intended use of the relevant application functionality, 
  and determine whether the ability to trigger arbitrary external service interactions is intended behavior. 
  If so, you should be aware of the types of attacks that can be performed via this behavior and take appropriate measures. 
  These measures might include blocking network access from the application server to other internal systems, and hardening the application server itself to remove any services available on the local loopback adapter.</p>
<p>If the ability to trigger arbitrary external service interactions is not intended behavior, then you should implement a whitelist of permitted services and hosts, and block any interactions that do not appear on this whitelist.</p>"#),
        references: &[
            Reference { title: r#"Burp Collaborator"#, url: r#"https://portswigger.net/blog/introducing-burp-collaborator"# },
            Reference { title: r#"Out-of-band application security testing (OAST)"#, url: r#"https://portswigger.net/burp/application-security-testing/oast"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CWE-406: Insufficient Control of Network Message Volume (Network Amplification)"#, url: r#"https://cwe.mitre.org/data/definitions/406.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4194560,
        declared_type_index: 4194560,
        name: r#"Referer-dependent response"#,
        typical_severity: Severity::Info,
        description: r#"<p>Application responses may depend systematically on the presence or absence of the Referer header in requests. This behavior does not necessarily constitute a security vulnerability, and you should investigate the nature of and reason for the differential responses to determine whether a vulnerability is present.</p>
<p>Common explanations for Referer-dependent responses include: </p>
<ul><li>Referer-based access controls, where the application assumes that if you have arrived from one privileged location then you are authorized to access another privileged location. These controls can be trivially defeated by supplying an accepted Referer header in requests for the vulnerable function.</li><li>Attempts to prevent cross-site request forgery attacks by verifying that requests to perform privileged actions originated from within the application itself and not from some external location. Such defenses are often not robust, and can be bypassed by removing the Referer header entirely.</li>
<li>Delivery of Referer-tailored content, such as welcome messages to visitors from specific domains, search-engine optimization (SEO) techniques, and other ways of tailoring the user's experience. Such behaviors often have no security impact; however, unsafe processing of the Referer header may introduce vulnerabilities such as SQL injection and cross-site scripting. If parts of the document (such as META keywords) are updated based on search engine queries contained in the Referer header, then the application may be vulnerable to persistent code injection attacks, in which search terms are manipulated to cause malicious content to appear in responses served to other application users.</li></ul>"#,
        remediation: Some(r#"<p>The Referer header is not a robust foundation on which to build access controls. Any such measures should be replaced with more secure alternatives that are not vulnerable to Referer spoofing.</p>
<p>If the contents of responses is updated based on Referer data, then the same defenses against malicious input should be employed here as for any other kinds of user-supplied data. </p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CWE-213: Intentional Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/213.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4194576,
        declared_type_index: 4194576,
        name: r#"Spoofable client IP address"#,
        typical_severity: Severity::Info,
        description: r#"<p>
If an application trusts an HTTP request header like X-Forwarded-For to accurately specify the remote IP address of the connecting client, then malicious clients can spoof their IP address. This behavior does not necessarily constitute a security vulnerability, however some applications use client IP addresses to enforce access controls and rate limits. For example, an application might expose administrative functionality only to clients connecting from the local IP address of the server, or allow a certain number of failed login attempts from each unique IP address.
Consider reviewing relevant functionality to determine whether this might be the case. </p>"#,
        remediation: Some(r#"<p>HTTP request headers such as X-Forwarded-For, True-Client-IP, and X-Real-IP are not a robust foundation on which to build any security measures, such as access controls. Any such measures should be replaced with more secure alternatives that are not vulnerable to spoofing.</p>
<p>If the platform application server returns incorrect information about the client's IP address due to the presence of any particular HTTP request header, then the server may need to be reconfigured, or an alternative method of identifying clients should be used. </p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4194592,
        declared_type_index: 4194592,
        name: r#"User agent-dependent response"#,
        typical_severity: Severity::Info,
        description: r#"<p>Application responses may depend systematically on the value of the User-Agent header in requests. This behavior does not itself constitute a security vulnerability, but may point towards additional attack surface within the application, which may contain vulnerabilities.</p>
<p>This behavior often arises because applications provide different user interfaces for desktop and mobile users. Mobile interfaces have often been less thoroughly tested for vulnerabilities such as cross-site scripting, and often have simpler authentication and session handling mechanisms that may contain problems that are not present in the full interface.</p>
<p>To review the interface provided by the alternate User-Agent header, you can configure a match/replace rule in Burp Proxy to modify the User-Agent header in all requests, and then browse the application in the normal way using your normal browser. </p>"#,
        remediation: None,
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4194816,
        declared_type_index: 4194816,
        name: r#"Password returned in later response"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Some applications return passwords submitted to the application in clear form in later responses. This behavior increases the risk that users' passwords will be captured by an attacker. Many types of vulnerability, such as weaknesses in session handling, broken access controls, and cross-site scripting, could enable an attacker to leverage this behavior to retrieve the passwords of other application users. This possibility typically exacerbates the impact of those other vulnerabilities, and in some situations can enable an attacker to quickly compromise the entire application.</p>
<p>Vulnerabilities that result in the disclosure of users' passwords can result in compromises that are extremely difficult to investigate due to obscured audit trails. Even if the application itself only handles non-sensitive information, exposing passwords puts users who have re-used their password elsewhere at risk.</p>"#,
        remediation: Some(r#"<p>There is usually no good reason for an application to return users' passwords in its responses. If user impersonation is a business requirement this would be better implemented as a custom function with associated logging.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-204: Response Discrepancy Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/204.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4195072,
        declared_type_index: 4195072,
        name: r#"Password submitted using GET method"#,
        typical_severity: Severity::Low,
        description: r#"<p>Some applications use the GET method to submit passwords, which are transmitted within the query string of the requested URL. Sensitive information within URLs may be logged in various locations, including the user's browser, the web server, and any forward or reverse proxy servers between the two endpoints. URLs may also be displayed on-screen, bookmarked or emailed around by users. They may be disclosed to third parties via the Referer header when any off-site links are followed. Placing passwords into the URL increases the risk that they will be captured by an attacker.</p>
<p>Vulnerabilities that result in the disclosure of users' passwords can result in compromises that are extremely difficult to investigate due to obscured audit trails. Even if the application itself only handles non-sensitive information, exposing passwords puts users who have re-used their password elsewhere at risk.</p>"#,
        remediation: Some(r#"<p>All forms submitting passwords should use the POST method. To achieve this, applications should specify the method attribute of the FORM tag as <b>method="POST"</b>. It may also be necessary to modify the corresponding server-side form handler to ensure that submitted passwords are properly retrieved from the message body, rather than the URL.
</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-598: Information Exposure Through Query Strings in GET Request"#, url: r#"https://cwe.mitre.org/data/definitions/598.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4195328,
        declared_type_index: 4195328,
        name: r#"Password returned in URL query string"#,
        typical_severity: Severity::Low,
        description: r#"<p>The application responds to login submissions with a link containing the user's password within the URL query string. Sensitive information within URLs may be logged in various locations, including the user's browser, the web server, and any forward or reverse proxy servers between the two endpoints. URLs may also be displayed on-screen, bookmarked or emailed around by users. They may be disclosed to third parties via the Referer header when any off-site links are followed. Placing passwords into the URL increases the risk that they will be captured by an attacker.</p>
<p>Vulnerabilities that result in the disclosure of users' passwords can result in compromises that are extremely difficult to investigate due to obscured audit trails. Even if the application itself only handles non-sensitive information, exposing passwords puts users who have re-used their password elsewhere at risk.</p>"#,
        remediation: Some(r#"<p>The application should never transmit any sensitive information within the URL query string. There is no good reason for a login mechanism to echo passwords back to the user, and the mechanism should be modified to remove this behavior.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-598: Information Exposure Through Query Strings in GET Request"#, url: r#"https://cwe.mitre.org/data/definitions/598.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4195456,
        declared_type_index: 4195456,
        name: r#"SQL statement in request parameter"#,
        typical_severity: Severity::Medium,
        description: r#"<p>HTTP requests sometimes contain SQL syntax. If this is incorporated into a SQL query and executed by the server, then the application is almost certainly vulnerable to SQL injection.</p>
<p>When SQL-like syntax is observed, you should verify whether the request contains a genuine SQL query and whether this is being executed by the server. </p>"#,
        remediation: Some(r#"<p>Applications should not incorporate any user-controllable data directly into SQL queries. Parameterized queries (also known as prepared statements) should be used to safely insert data into predefined queries. In no circumstances should users be able to control or modify the structure of the SQL query itself.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: SQL injection"#, url: r#"https://portswigger.net/web-security/sql-injection"# },
            Reference { title: r#"Using Burp to Test for Injection Flaws"#, url: r#"https://support.portswigger.net/customer/portal/articles/1965677-using-burp-to-test-for-injection-flaws"# },
            Reference { title: r#"Web Security Academy: SQL Injection Cheat Sheet"#, url: r#"https://portswigger.net/web-security/sql-injection/cheat-sheet"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-598: Information Exposure Through Query Strings in GET Request"#, url: r#"https://cwe.mitre.org/data/definitions/598.html"# },
            Classification { title: r#"CAPEC-66: SQL Injection"#, url: r#"https://capec.mitre.org/data/definitions/66.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4195584,
        declared_type_index: 4195584,
        name: r#"Cross-domain POST"#,
        typical_severity: Severity::Info,
        description: r#"<p>Applications sometimes use POST requests to transfer sensitive information from one domain to another. This does not necessarily constitute a security vulnerability, but it creates a trust relationship between the two domains. Data transmitted between domains should be reviewed to determine whether the originating application should be trusting the receiving domain with this information.</p>"#,
        remediation: None,
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4195840,
        declared_type_index: 4195840,
        name: r#"ASP.NET ViewState without MAC enabled"#,
        typical_severity: Severity::High,
        description: r#"<p>The ViewState is a mechanism built in to the ASP.NET platform for persisting elements of the user interface and other data across successive requests. The data to be persisted is serialized by the server and transmitted via a hidden form field. When it is posted back to the server, the ViewState parameter is deserialized and the data is retrieved.</p>
<p>By default, the serialized value is signed by the server to prevent tampering by the user; however, this behavior can be disabled by setting the Page.EnableViewStateMac property to false. If this is done, then an attacker can modify the contents of the ViewState and cause arbitrary data to be deserialized and processed by the server. An attacker may be able to execute arbitrary code on the server by supplying a gadget chain. Also, if the ViewState contains any items that are critical to the server's processing of the request, then this may result in a direct security exposure.</p>
<p>You should try to identify a valid gadget chain to take control of the server and, failing that, review the contents of the ViewState to determine whether it contains any critical items that can be manipulated to attack the application. </p>"#,
        remediation: Some(r#"<p>There is no good reason to disable the default ASP.NET behavior in which the ViewState is signed to prevent tampering. To ensure that this occurs, you should set the Page.EnableViewStateMac property to true on any pages where the ViewState is not currently signed.</p>"#),
        references: &[
            Reference { title: r#"Exploiting Deserialisation in ASP.NET via ViewState"#, url: r#"https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/"# },
            Reference { title: r#"Web Security Academy: Insecure deserialization"#, url: r#"https://portswigger.net/web-security/deserialization"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-642: External Control of Critical State Data"#, url: r#"https://cwe.mitre.org/data/definitions/642.html"# },
            Classification { title: r#"CAPEC-586: Object Injection"#, url: r#"https://capec.mitre.org/data/definitions/586.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4196096,
        declared_type_index: 4196096,
        name: r#"XML entity expansion"#,
        typical_severity: Severity::Medium,
        description: r#"<p>XML entity expansion vulnerabilities arise because the XML specification allows XML documents to define entities that reference other entities defined within the document. If this is done recursively to a significant depth, then the XML parser will consume exponentially increasing amounts of memory and processor resources as each level of recursion is processed. This might result in a denial-of-service condition, causing the entire application to stop functioning.</p>
<p><b>Note:</b> To avoid causing an actual denial-of-service, Burp Suite merely verifies that entities are being recursively expanded to a modest depth. It is possible that reported applications are not actually vulnerable because they are designed to prevent entity expansion beyond a given depth.
</p>"#,
        remediation: Some(r#"<p>XML entity expansion makes use of the DOCTYPE tag to define the injected entities. XML parsers can usually be configured to disable support for this tag. You should consult the documentation for your XML parsing library to determine how to disable this feature.</p>
<p>It may also be possible to use input validation to block input containing a DOCTYPE tag. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: XXE injection"#, url: r#"https://portswigger.net/web-security/xxe"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')"#, url: r#"https://cwe.mitre.org/data/definitions/776.html"# },
            Classification { title: r#"CAPEC-197: XML Entity Expansion"#, url: r#"https://capec.mitre.org/data/definitions/197.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4196352,
        declared_type_index: 4196352,
        name: r#"Long redirection response"#,
        typical_severity: Severity::Info,
        description: r#"<p>The application returned a redirection response containing a "long" message body. Ordinarily, this content is not displayed to the user, because the browser automatically follows the redirection.</p>
<p>Occasionally, redirection responses contain sensitive data. For example, if the user requests a page that they are not authorized to view, then an application might issue a redirection to a different page, but also include the contents of the prohibited page.</p>
<p>You should review the contents of the response to determine whether it contains anything sensitive. </p>"#,
        remediation: Some(r#"<p>In cases where the application handles requests for unauthorized content by redirecting to a different URL, the application should ensure that no sensitive content is included within the redirection response. Depending on the application and the platform, this might involve checking for proper authorization earlier in the request handling logic, or using a different API to perform the redirection.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-698: Execution After Redirect (EAR)"#, url: r#"https://cwe.mitre.org/data/definitions/698.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4196608,
        declared_type_index: 4196608,
        name: r#"Serialized object in HTTP message"#,
        typical_severity: Severity::High,
        description: r#"<p>Applications may submit a serialized object in a request parameter. This behavior can expose the application in various ways, including:</p>
<ul>
<li>Any sensitive data contained within the object can be viewed by the user.</li><li>An attacker may be able to interfere with server-side logic by tampering with the contents of the object and re-serializing it.</li><li>An attacker may be able to cause unauthorized code execution on the server, by controlling the server-side function that is invoked when the object is processed.</li></ul>
<p>Actual exploitation of any code execution vulnerabilities arising from the application's use of serialized objects will typically require the attacker to have access to the source code of the server-side application. This may mitigate the practical impact of this issue in many situations. However, it is still highly recommended to fix the underlying vulnerability. Vulnerabilities in native deserialization functions often allow practical exploitation without source code access.</p>"#,
        remediation: Some(r#"<p>The best way to avoid vulnerabilities that arise from the use of serialized objects is not to pass these in request parameters, or expose them in any other way to the client. Generally, it is possible to transmit application data in plain non-serialized form, and handle it with the same precautions that apply to all client-submitted data. If it is considered unavoidable to place serialized objects into request parameters, then it may be possible to prevent attacks by also placing a server-generated cryptographic signature of the object into the same request, and validating the signature before performing deserialization or other processing on the object.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Insecure deserialization"#, url: r#"https://portswigger.net/web-security/deserialization"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-502: Deserialization of Untrusted Data"#, url: r#"https://cwe.mitre.org/data/definitions/502.html"# },
            Classification { title: r#"CAPEC-586: Object Injection"#, url: r#"https://capec.mitre.org/data/definitions/586.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4196864,
        declared_type_index: 4196864,
        name: r#"Duplicate cookies set"#,
        typical_severity: Severity::Info,
        description: r#"<p>The response contains two or more Set-Cookie headers that attempt to set the same cookie to different values. Browsers will only accept one of these values, typically the value in the last header. The presence of the duplicate headers may indicate a programming error.</p>"#,
        remediation: None,
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4197120,
        declared_type_index: 4197120,
        name: r#"Input returned in response (stored)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Retrieval of stored input arises when user input is stored and later embedded into the application's responses. </p><p>Input being returned in application responses is not a vulnerability in its own right. However, it is a prerequisite for many client-side vulnerabilities, including cross-site scripting, open redirection, content spoofing, and response header injection. Additionally, some server-side vulnerabilities such as SQL injection are often easier to identify and exploit when input is returned in responses. In applications where input retrieval is rare and the environment is resistant to automated testing (for example, due to a web application firewall), it might be worth subjecting instances of it to focused manual testing. </p>

<p>Vulnerabilities resulting from retrieval of stored input  are typically more serious than the equivalent reflected vulnerabilities because they do not require a separate delivery mechanism in order to reach target users. Depending on the affected functionality, ordinary users may be exploited during normal use of the application. Note that automated detection of stored data retrieval cannot reliably determine whether input that is persisted within the application can be retrieved by any other user, only by authenticated users, or only by the attacker themselves. You should review the functionality in which the vulnerability appears to determine whether the application's behavior can feasibly be used to compromise other application users. </p>"#,
        remediation: None,
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4197376,
        declared_type_index: 4197376,
        name: r#"Input returned in response (reflected)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Reflection of input arises when data is copied from a request and echoed into the application's immediate response.</p><p>Input being returned in application responses is not a vulnerability in its own right. However, it is a prerequisite for many client-side vulnerabilities, including cross-site scripting, open redirection, content spoofing, and response header injection. Additionally, some server-side vulnerabilities such as SQL injection are often easier to identify and exploit when input is returned in responses. In applications where input retrieval is rare and the environment is resistant to automated testing (for example, due to a web application firewall), it might be worth subjecting instances of it to focused manual testing. </p>"#,
        remediation: None,
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4197632,
        declared_type_index: 4197632,
        name: r#"Suspicious input transformation (reflected)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Suspicious input transformation arises when an application receives user input, transforms it in some way, and then performs further processing on the result. The types of transformations that can lead to problems include decoding common formats, such as UTF-8 and URL-encoding, or processing of escape sequences, such as backslash escaping. </p>
<p>Performing these input transformations does not constitute a vulnerability in its own right, but might lead to problems in conjunction with other application behaviors. An attacker might be able to bypass input filters by suitably encoding their payloads, if the input is decoded after the input filters have been applied. Or an attacker might be able to interfere with other data that is concatenated onto their input, by finishing their input with the start of a multi-character encoding or escape sequence, the transformation of which will consume the start of the following data.</p>"#,
        remediation: Some(r#"<p>Review the transformation that is being applied, to understand whether this is intended and desirable behavior given the nature of the application functionality, and whether it gives rise to any vulnerabilities in relation to  bypassing of input filters or character consumption.</p>"#),
        references: &[
            Reference { title: r#"Backslash Powered Scanning: Hunting Unknown Vulnerability Classes"#, url: r#"https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4197888,
        declared_type_index: 4197888,
        name: r#"Suspicious input transformation (stored)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Suspicious input transformation arises when an application receives user input, transforms it in some way, and then performs further processing on the result. The types of transformations that can lead to problems include decoding common formats, such as UTF-8 and URL-encoding, or processing of escape sequences, such as backslash escaping. </p>
<p>Performing these input transformations does not constitute a vulnerability in its own right, but might lead to problems in conjunction with other application behaviors. An attacker might be able to bypass input filters by suitably encoding their payloads, if the input is decoded after the input filters have been applied. Or an attacker might be able to interfere with other data that is concatenated onto their input, by finishing their input with the start of a multi-character encoding or escape sequence, the transformation of which will consume the start of the following data.</p>

<p>Stored suspicious input transformation arises when the transformed input is stored and later embedded into the application's responses.</p>"#,
        remediation: Some(r#"<p>Review the transformation that is being applied, to understand whether this is intended and desirable behavior given the nature of the application functionality, and whether it gives rise to any vulnerabilities in relation to  bypassing of input filters or character consumption.</p>"#),
        references: &[
            Reference { title: r#"Backslash Powered Scanning: Hunting Unknown Vulnerability Classes"#, url: r#"https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 4198144,
        declared_type_index: 4198144,
        name: r#"Request URL override"#,
        typical_severity: Severity::Info,
        description: r#"<p>Some applications and frameworks support HTTP headers that can be used to override parts of the request URL, potentially affecting the routing and processing of the request.</p>
<p>Intermediate systems are often oblivious to these headers. In the case of reverse proxies and web application firewalls, this can lead to security rulesets being bypassed. If a caching system is in place, this may enable cache poisoning attacks. These headers may also enable forging of log entries. </p>
<p>Even if the application is intended to be accessed directly, some visitors may be using a corporate proxy enabling localised cache poisoning. </p>"#,
        remediation: Some(r#"<p>To fully resolve this issue, locate the component that processes the affected headers, and disable it entirely.
If you are using a framework, applying any pending security updates may do this for you.</p>
<p>If this isn't practical, an alternative workaround is to configure an intermediate system to automatically strip the affected headers before they are processed.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: HTTP Host header attacks"#, url: r#"https://portswigger.net/web-security/host-header"# },
            Reference { title: r#"Web Security Academy: Web cache poisoning"#, url: r#"https://portswigger.net/web-security/web-cache-poisoning"# },
            Reference { title: r#"Practical Web Cache Poisoning"#, url: r#"https://portswigger.net/blog/practical-web-cache-poisoning"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-436: Interpretation Conflict"#, url: r#"https://cwe.mitre.org/data/definitions/436.html"# },
            Classification { title: r#"CAPEC-141: Cache Poisoning"#, url: r#"https://capec.mitre.org/data/definitions/141.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5243008,
        declared_type_index: 5243008,
        name: r#"Vulnerable JavaScript dependency"#,
        typical_severity: Severity::Low,
        description: r#"<p>
The use of third-party JavaScript libraries can introduce a range of DOM-based vulnerabilities, including some that can be used to hijack user accounts like DOM-XSS. 
</p>

<p>
Common JavaScript libraries typically enjoy the benefit of being heavily audited. This may mean that bugs are quickly identified and patched upstream, resulting in a steady stream of security updates that need to be applied. Although it may be tempting to ignore updates, using a library with missing security patches can make your website exceptionally easy to exploit. Therefore, it's important to ensure that any available security updates are applied promptly. 
</p>
<p>
Some library vulnerabilities expose every application that imports the library, but others only affect applications that use certain library features. Accurately identifying which library vulnerabilities apply to your website can be difficult, so we recommend applying all available security updates regardless.
</p>"#,
        remediation: Some(r#"<p>Develop a patch-management strategy to ensure that security updates are promptly applied to all third-party libraries in your application. Also, consider reducing your attack surface by removing any libraries that are no longer in use.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-1104: Use of Unmaintained Third Party Components"#, url: r#"https://cwe.mitre.org/data/definitions/1104.html"# },
            Classification { title: r#"A9: Using Components with Known Vulnerabilities"#, url: r#"https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"# },
        ],
    },
    IssueDefinition {
        type_index: 5243136,
        declared_type_index: 5243136,
        name: r#"Open redirection (reflected)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Open redirection vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.</p>"#,
        remediation: Some(r#"<p>If possible, applications should avoid incorporating user-controllable data into redirection targets. In many cases, this behavior can be avoided in two ways:</p>
<ul>
  <li>Remove the redirection function from the application, and replace links to it with direct links to the relevant target URLs.</li>
  <li>Maintain a server-side list of all URLs that are permitted for redirection. Instead of passing the target URL as a parameter to the redirector, pass an index into this list.</li>
</ul>
<p>If it is considered unavoidable for the redirection function to receive user-controllable input and incorporate this into the redirection target, one of the following measures should be used to minimize the risk of redirection attacks:</p>
<ul>
  <li>The application should use relative URLs in all of its redirects, and the redirection function should strictly validate that the URL received is a relative URL.</li>
  <li>The application should use URLs relative to the web root for all of its redirects, and the redirection function should validate that the URL received starts with a slash character. It should then prepend http://yourdomainname.com to the URL before issuing the redirect.</li>
  <li>The application should use absolute URLs for all of its redirects, and the redirection function should verify that the user-supplied URL begins with http://yourdomainname.com/ before issuing the redirect.</li>
</ul>"#),
        references: &[
            Reference { title: r#"Using Burp to Test for Open Redirections"#, url: r#"https://support.portswigger.net/customer/portal/articles/1965733-Methodology_Testing%20for%20Open%20Redirections.html"# },
            Reference { title: r#"Fun With Redirects"#, url: r#"https://www.owasp.org/images/b/b9/OWASP_Appsec_Research_2010_Redirects_XSLJ_by_Sirdarckcat_and_Thornmaker.pdf"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"#, url: r#"https://cwe.mitre.org/data/definitions/601.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5243137,
        declared_type_index: 5243137,
        name: r#"Open redirection (stored)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Open redirection vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.</p>"#,
        remediation: Some(r#"<p>If possible, applications should avoid incorporating user-controllable data into redirection targets. In many cases, this behavior can be avoided in two ways:</p>
<ul>
  <li>Remove the redirection function from the application, and replace links to it with direct links to the relevant target URLs.</li>
  <li>Maintain a server-side list of all URLs that are permitted for redirection. Instead of passing the target URL as a parameter to the redirector, pass an index into this list.</li>
</ul>
<p>If it is considered unavoidable for the redirection function to receive user-controllable input and incorporate this into the redirection target, one of the following measures should be used to minimize the risk of redirection attacks:</p>
<ul>
  <li>The application should use relative URLs in all of its redirects, and the redirection function should strictly validate that the URL received is a relative URL.</li>
  <li>The application should use URLs relative to the web root for all of its redirects, and the redirection function should validate that the URL received starts with a slash character. It should then prepend http://yourdomainname.com to the URL before issuing the redirect.</li>
  <li>The application should use absolute URLs for all of its redirects, and the redirection function should verify that the user-supplied URL begins with http://yourdomainname.com/ before issuing the redirect.</li>
</ul>

<p>Stored open redirection vulnerabilities arise when the applicable input was submitted in an previous request and stored by the application. This is often more serious than reflected open redirection because an attacker might be able to place persistent input into the application which, when viewed by other users, causes their browser to invisibly redirect to a domain of the attacker's choice.</p>"#),
        references: &[
            Reference { title: r#"Using Burp to Test for Open Redirections"#, url: r#"https://support.portswigger.net/customer/portal/articles/1965733-Methodology_Testing%20for%20Open%20Redirections.html"# },
            Reference { title: r#"Fun With Redirects"#, url: r#"https://www.owasp.org/images/b/b9/OWASP_Appsec_Research_2010_Redirects_XSLJ_by_Sirdarckcat_and_Thornmaker.pdf"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"#, url: r#"https://cwe.mitre.org/data/definitions/601.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5243152,
        declared_type_index: 5243152,
        name: r#"Open redirection (DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>

<p>DOM-based open redirection arises when a script  writes controllable data into the target of a redirection in an unsafe way. An attacker may be able to use the vulnerability to  construct a URL that, if visited by another application user, will cause a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.</p>
<p><b>Note:</b> If an attacker is able to control the start of the string that is passed to the redirection API, then it may be possible to escalate this vulnerability into a JavaScript injection attack, by using a URL with the javascript: pseudo-protocol to execute arbitrary script code when the URL is processed by the browser.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based open redirection vulnerabilities is not to dynamically set redirection targets using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a redirection target. In general, this is best achieved by using a whitelist of URLs that are permitted redirection targets, and strictly validating the target against this list before performing the redirection.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Open redirection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/open-redirection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"#, url: r#"https://cwe.mitre.org/data/definitions/601.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5243153,
        declared_type_index: 5243153,
        name: r#"Open redirection (reflected DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM-based open redirection arises when a script  writes controllable data into the target of a redirection in an unsafe way. An attacker may be able to use the vulnerability to  construct a URL that, if visited by another application user, will cause a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.</p>
<p><b>Note:</b> If an attacker is able to control the start of the string that is passed to the redirection API, then it may be possible to escalate this vulnerability into a JavaScript injection attack, by using a URL with the javascript: pseudo-protocol to execute arbitrary script code when the URL is processed by the browser.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based open redirection vulnerabilities is not to dynamically set redirection targets using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a redirection target. In general, this is best achieved by using a whitelist of URLs that are permitted redirection targets, and strictly validating the target against this list before performing the redirection.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Open redirection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/open-redirection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"#, url: r#"https://cwe.mitre.org/data/definitions/601.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5243154,
        declared_type_index: 5243154,
        name: r#"Open redirection (stored DOM-based)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM-based open redirection arises when a script  writes controllable data into the target of a redirection in an unsafe way. An attacker may be able to use the vulnerability to  construct a URL that, if visited by another application user, will cause a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.</p>
<p><b>Note:</b> If an attacker is able to control the start of the string that is passed to the redirection API, then it may be possible to escalate this vulnerability into a JavaScript injection attack, by using a URL with the javascript: pseudo-protocol to execute arbitrary script code when the URL is processed by the browser.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based open redirection vulnerabilities is not to dynamically set redirection targets using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a redirection target. In general, this is best achieved by using a whitelist of URLs that are permitted redirection targets, and strictly validating the target against this list before performing the redirection.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Open redirection (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/open-redirection"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"#, url: r#"https://cwe.mitre.org/data/definitions/601.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5243392,
        declared_type_index: 5243392,
        name: r#"TLS cookie without secure flag set"#,
        typical_severity: Severity::Medium,
        description: r#"<p>If the secure flag is set on a cookie, then browsers will not submit the cookie in any requests that use an unencrypted HTTP connection, thereby preventing the cookie from being trivially intercepted by an attacker monitoring network traffic. If the secure flag is not set, then the cookie will be transmitted in clear-text if the user visits any HTTP URLs within the cookie's scope. An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site. Even if the domain that issued the cookie does not host any content that is accessed over HTTP, an attacker may be able to use links of the form http://example.com:443/ to perform the same attack.</p>
<p>To exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.</p>"#,
        remediation: Some(r#"<p>The secure flag should be set on all cookies that are used for transmitting sensitive data when accessing content over HTTPS. If cookies are used to transmit session tokens, then areas of the application that are accessed over HTTPS should employ their own session handling mechanism, and the session tokens used should never be transmitted over unencrypted communications.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"#, url: r#"https://cwe.mitre.org/data/definitions/614.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5243648,
        declared_type_index: 5243648,
        name: r#"Cookie scoped to parent domain"#,
        typical_severity: Severity::Low,
        description: r#"<p>A cookie's domain attribute determines which domains can access the cookie. Browsers will automatically submit the cookie in requests to in-scope domains, and those domains will also be able to access the cookie via JavaScript. If a cookie is scoped to a parent domain, then that cookie will be accessible by the parent domain and also by any other subdomains of the parent domain. If the cookie contains sensitive data (such as a session token) then this data may be accessible by less trusted or less secure applications residing at those domains, leading to a security compromise.</p>"#,
        remediation: Some(r#"<p>By default, cookies are scoped to the issuing domain, and on IE/Edge to subdomains. If you remove the explicit domain attribute from your Set-cookie directive, then the cookie will have this default scope, which is safe and appropriate in most situations. If you particularly need a cookie to be accessible by a parent domain, then you should thoroughly review the security of the applications residing on that domain and its subdomains, and confirm that you are willing to trust the people and systems that support those applications.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5243904,
        declared_type_index: 5243904,
        name: r#"Cross-domain Referer leakage"#,
        typical_severity: Severity::Info,
        description: r#"<p>When a web browser makes a request for a resource, it typically adds an HTTP header, called the "Referer" header, indicating the URL of the resource from which the request originated. This occurs in numerous situations, for example when a web page loads an image or script, or when a user clicks on a link or submits a form.</p>
<p>If the resource being requested resides on a different domain, then the Referer header is still generally included in the cross-domain request. If the originating URL contains any sensitive information within its query string, such as a session token, then this information will be transmitted to the other domain. If the other domain is not fully trusted by the application, then this may lead to a security compromise.</p>
<p>You should review the contents of the information being transmitted to other domains, and also determine whether those domains are fully trusted by the originating application.</p>
<p>Today's browsers may withhold the Referer header in some situations (for example, when loading a non-HTTPS resource from a page that was loaded over HTTPS, or when a Refresh directive is issued), but this behavior should not be relied upon to protect the originating URL from disclosure.</p>
<p>Note also that if users can author content within the application then an attacker may be able to inject links referring to a domain they control in order to capture data from URLs used within the application. </p>"#,
        remediation: Some(r#"<p>Applications should never transmit any sensitive information within the URL query string. In addition to being leaked in the Referer header, such information may be logged in various locations and may be visible on-screen to untrusted parties. If placing sensitive information in the URL is unavoidable, consider using the Referrer-Policy HTTP header to reduce the chance of it being disclosed to third parties.
</p>"#),
        references: &[
            Reference { title: r#"Referer Policy"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"# },
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5244160,
        declared_type_index: 5244160,
        name: r#"Cross-domain script include"#,
        typical_severity: Severity::Info,
        description: r#"<p>When an application includes a script from an external domain, this script is executed by the browser within the security context of the invoking application. The script can therefore do anything that the application's own scripts can do, such as accessing application data and performing actions within the context of the current user.</p>
<p>If you include a script from an external domain, then you are trusting that domain with the data and functionality of your application, and you are trusting the domain's own security to prevent an attacker from modifying the script to perform malicious actions within your application. </p>"#,
        remediation: Some(r#"<p>Scripts should ideally not be included from untrusted domains. Applications that rely on static third-party scripts should consider using Subresource Integrity to make browsers verify them, or copying the contents of these scripts onto their own domain and including them from there. If that is not possible (e.g. for licensing reasons) then consider reimplementing the script's functionality within application code.</p>"#),
        references: &[
            Reference { title: r#"Subresource Integrity"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-829: Inclusion of Functionality from Untrusted Control Sphere"#, url: r#"https://cwe.mitre.org/data/definitions/829.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5244416,
        declared_type_index: 5244416,
        name: r#"Cookie without HttpOnly flag set"#,
        typical_severity: Severity::Low,
        description: r#"<p>If the HttpOnly attribute is set on a cookie, then the cookie's value cannot be read or set by client-side JavaScript. This measure makes certain client-side attacks, such as cross-site scripting, slightly harder to exploit by preventing them from trivially capturing the cookie's value via an injected script.</p>"#,
        remediation: Some(r#"<p>There is usually no good reason not to set the HttpOnly flag on all cookies. Unless you specifically require legitimate client-side scripts within your application to read or set a cookie's value, you should set the HttpOnly flag by including this attribute within the relevant Set-cookie directive.</p>
<p>You should be aware that the restrictions imposed by the HttpOnly flag can potentially be circumvented in some circumstances, and that numerous other serious attacks can be delivered by client-side script injection, aside from simple cookie stealing. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Exploiting XSS vulnerabilities"#, url: r#"https://portswigger.net/web-security/cross-site-scripting/exploiting"# },
            Reference { title: r#"HttpOnly effectiveness"#, url: r#"https://portswigger.net/research/web-storage-the-lesser-evil-for-session-tokens#httponly"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies"#, url: r#"https://capec.mitre.org/data/definitions/31.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5244672,
        declared_type_index: 5244672,
        name: r#"Session token in URL"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Sensitive information within URLs may be logged in various locations, including the user's browser, the web server, and any forward or reverse proxy servers between the two endpoints. URLs may also be displayed on-screen, bookmarked or emailed around by users. They may be disclosed to third parties via the Referer header when any off-site links are followed. Placing session tokens into the URL increases the risk that they will be captured by an attacker.</p>"#,
        remediation: Some(r#"<p>Applications should use an alternative mechanism for transmitting session tokens, such as HTTP cookies or hidden fields in forms that are submitted using the POST method.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
            Classification { title: r#"CWE-384: Session Fixation"#, url: r#"https://cwe.mitre.org/data/definitions/384.html"# },
            Classification { title: r#"CWE-598: Information Exposure Through Query Strings in GET Request"#, url: r#"https://cwe.mitre.org/data/definitions/598.html"# },
            Classification { title: r#"CAPEC-593: Session Hijacking"#, url: r#"https://capec.mitre.org/data/definitions/593.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5244928,
        declared_type_index: 5244928,
        name: r#"Password field with autocomplete enabled"#,
        typical_severity: Severity::Low,
        description: r#"<p>Most browsers have a facility to remember user credentials that are entered into HTML forms. This function can be configured by the user and also by applications that employ user credentials. If the function is enabled, then credentials entered by the user are stored on their local computer and retrieved by the browser on future visits to the same application.</p>
<p>The stored credentials can be captured by an attacker who gains control over the user's computer. Further, an attacker who finds a separate application vulnerability such as cross-site scripting may be able to exploit this to retrieve a user's browser-stored credentials. </p>"#,
        remediation: Some(r#"<p>To prevent browsers from storing credentials entered into HTML forms, include the attribute <b>autocomplete="off"</b> within the FORM tag (to protect all form fields) or within the relevant INPUT tags (to protect specific individual fields).</p>
<p>Please note that modern web browsers may ignore this directive. In spite of this there is a chance that not disabling autocomplete may cause problems obtaining PCI compliance.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245184,
        declared_type_index: 5245184,
        name: r#"Password value set in cookie"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Some applications issue a cookie containing the clear-text value of the password supplied by the user. This behavior increases the risk that users' passwords will be captured by an attacker. Any cookie-stealing vulnerabilities within the application or browser would enable an attacker to steal the user's credentials to the application.</p>
<p>Vulnerabilities that result in the disclosure of users' passwords can result in compromises that are extremely difficult to investigate due to obscured audit trails. Even if the application itself only handles non-sensitive information, exposing passwords puts users who have re-used their password elsewhere at risk.</p>"#,
        remediation: Some(r#"<p>Applications should not store user credentials within any client-side mechanism such as cookies.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-287: Improper Authentication"#, url: r#"https://cwe.mitre.org/data/definitions/287.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245312,
        declared_type_index: 5245312,
        name: r#"File upload functionality"#,
        typical_severity: Severity::Info,
        description: r#"<p>File upload functionality is commonly associated with a number of vulnerabilities, including:</p>
<ul>
<li>File path traversal</li><li>Persistent cross-site scripting</li><li>Placing of other client-executable code into the domain</li><li>Transmission of viruses and other malware</li><li>Denial of service</li></ul>
<p>You should review file upload functionality to understand its purpose, and establish whether uploaded content is ever returned to other application users, either through their normal usage of the application or by being fed a specific link by an attacker.</p>
<p>Some factors to consider when evaluating the security impact of this functionality include:</p>
<ul>
<li>Whether uploaded content can subsequently be downloaded via a URL within the application.</li><li>What Content-type and Content-disposition headers the application returns when the file's content is downloaded.</li><li>Whether it is possible to place executable HTML/JavaScript into the file, which executes when the file's contents are viewed.</li><li>Whether the application performs any filtering on the file extension or MIME type of the uploaded file.</li><li>Whether it is possible to construct a hybrid file containing both executable and non-executable content, to bypass any content filters - for example, a file containing both a GIF image and a Java archive (known as a GIFAR file).</li><li>What location is used to store uploaded content, and whether it is possible to supply a crafted filename to escape from this location.</li><li>Whether archive formats such as ZIP are unpacked by the application.</li><li>How the application handles attempts to upload very large files, or decompression bomb files.</li></ul>"#,
        remediation: Some(r#"<p>File upload functionality is not straightforward to implement securely. Some recommendations to consider in the design of this functionality include:</p>
<ul>
<li>Use a server-generated filename if storing uploaded files on disk.</li><li>Inspect the content of uploaded files, and enforce a whitelist of accepted, non-executable content types. Additionally, enforce a blacklist of common executable formats, to hinder hybrid file attacks.</li><li>Enforce a whitelist of accepted, non-executable file extensions.</li>
<li>If uploaded files are downloaded by users, supply an accurate non-generic Content-Type header, the X-Content-Type-Options: nosniff header, and also a Content-Disposition header that specifies that browsers should handle the file as an attachment.</li>
<li>Enforce a size limit on uploaded files (for defense-in-depth, this can be implemented both within application code and in the web server's configuration).</li><li>Reject attempts to upload archive formats such as ZIP.</li></ul>"#),
        references: &[
            Reference { title: r#"Various proof-of-concept files"#, url: r#"https://github.com/cure53/H5SC/tree/master/attachments"# },
            Reference { title: r#"An XSS polyglot attack"#, url: r#"http://labs.detectify.com/post/120088174539/building-an-xss-polyglot-through-swf-and-csp"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-434: Unrestricted Upload of File with Dangerous Type"#, url: r#"https://cwe.mitre.org/data/definitions/434.html"# },
            Classification { title: r#"CAPEC-17: Using Malicious Files"#, url: r#"https://capec.mitre.org/data/definitions/17.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245344,
        declared_type_index: 5245344,
        name: r#"Frameable response (potential Clickjacking)"#,
        typical_severity: Severity::Info,
        description: r#"<p>If a page fails to set an appropriate X-Frame-Options or Content-Security-Policy HTTP header, it might be possible for a page controlled by an attacker to load it within an iframe. This may enable a clickjacking attack, in which the attacker's page overlays the target application's interface with a different interface provided by the attacker. By inducing victim users to perform actions such as mouse clicks and keystrokes, the attacker can cause them to unwittingly carry out actions within the application that is being targeted. This technique allows the attacker to circumvent defenses against cross-site request forgery, and may result in unauthorized actions.</p>
<p>Note that some applications attempt to prevent these attacks from within the HTML page itself, using "framebusting" code. However, this type of defense is normally ineffective and can usually be circumvented by a skilled attacker.</p>
<p>You should determine whether any functions accessible within frameable pages can be used by application users to perform any sensitive actions within the application. </p>"#,
        remediation: Some(r#"<p>To effectively prevent framing attacks, the application should return a response header with the name <b>X-Frame-Options</b> and the value <b>DENY</b> to prevent framing altogether, or the value <b>SAMEORIGIN</b> to allow framing only by pages on the same origin as the response itself. Note that the SAMEORIGIN header can be partially bypassed if the application itself can be made to frame untrusted websites.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Clickjacking"#, url: r#"https://portswigger.net/web-security/clickjacking"# },
            Reference { title: r#"X-Frame-Options"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-693: Protection Mechanism Failure"#, url: r#"https://cwe.mitre.org/data/definitions/693.html"# },
            Classification { title: r#"CWE-1021: Improper Restriction of Rendered UI Layers or Frames"#, url: r#"https://cwe.mitre.org/data/definitions/1021.html"# },
            Classification { title: r#"CAPEC-103: Clickjacking"#, url: r#"https://capec.mitre.org/data/definitions/103.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245360,
        declared_type_index: 5245360,
        name: r#"Browser cross-site scripting filter disabled"#,
        typical_severity: Severity::Info,
        description: r#"<p>Some browsers, including Internet Explorer, contain built-in filters designed to protect against cross-site scripting (XSS) attacks. Applications can instruct browsers to disable this filter by setting the following response header:</p>
<p><b>X-XSS-Protection: 0</b></p>
<p>This behavior does not in itself constitute a vulnerability; in some cases XSS filters may themselves be leveraged to perform attacks against application users. However, in typical situations XSS filters do provide basic protection for application users against some XSS vulnerabilities in applications. The presence of this header should be reviewed to establish whether it affects the application's security posture. </p>"#,
        remediation: Some(r#"<p>Review whether the application needs to disable XSS filters. In most cases you can gain the protection provided by XSS filters without the associated risks by using the following response header:</p>
<p><b>X-XSS-Protection: 1; mode=block</b></p>
<p>When this header is set, browsers that detect an XSS attack will simply render a blank page instead of attempting to sanitize the injected script. This behavior is considerably less likely to introduce new security issues. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
            Reference { title: r#"Controlling the XSS Filter"#, url: r#"http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CAPEC-63: Cross-Site Scripting (XSS)"#, url: r#"https://capec.mitre.org/data/definitions/63.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245440,
        declared_type_index: 5245440,
        name: r#"HTTP TRACE method is enabled"#,
        typical_severity: Severity::Info,
        description: r#"<p>The HTTP TRACE  method is designed for diagnostic purposes. If enabled, the web server will respond to requests that use the TRACE method by echoing in its response the exact request that was received.</p>
<p>This behavior is often harmless, but occasionally leads to the disclosure of sensitive information such as internal authentication headers appended by reverse proxies. This functionality could historically be used to bypass the HttpOnly cookie flag on cookies, but this is no longer possible in modern web browsers. </p>"#,
        remediation: Some(r#"<p>The TRACE method should be disabled on production web servers.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure via TRACE method"#, url: r#"https://portswigger.net/web-security/information-disclosure/exploiting#information-disclosure-due-to-insecure-configuration"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245696,
        declared_type_index: 5245696,
        name: r#"Cookie manipulation (DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>

<p>DOM-based cookie manipulation arises when a  script writes controllable data into the value of a cookie. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will set an arbitrary value in the user's cookie.</p>
<p>The potential impact of the vulnerability depends on the role that the cookie plays within the application. If the cookie is used to control the behavior that results from certain user actions (for example, a 'production' versus 'demo' mode setting), then the attacker may be able to cause the user to perform unintended actions by manipulating the cookie's value. If the cookie is used to track the user's session, then the attacker may be able to perform a session fixation attack, in which they set the cookie's value to a valid token that they have obtained from the application, and then hijack the session during the victim user's subsequent interaction with the application.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based cookie manipulation vulnerabilities is not to dynamically write to cookies using data that originated from any untrusted source. This behavior should never be implemented for cookies that have any role in controlling privileged actions or user sessions within the application.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cookie manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/cookie-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-565: Reliance on Cookies without Validation and Integrity Checking"#, url: r#"https://cwe.mitre.org/data/definitions/565.html"# },
            Classification { title: r#"CWE-829: Inclusion of Functionality from Untrusted Control Sphere"#, url: r#"https://cwe.mitre.org/data/definitions/829.html"# },
            Classification { title: r#"CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies"#, url: r#"https://capec.mitre.org/data/definitions/31.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245697,
        declared_type_index: 5245697,
        name: r#"Cookie manipulation (reflected DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>DOM-based cookie manipulation arises when a  script writes controllable data into the value of a cookie. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will set an arbitrary value in the user's cookie.</p>
<p>The potential impact of the vulnerability depends on the role that the cookie plays within the application. If the cookie is used to control the behavior that results from certain user actions (for example, a 'production' versus 'demo' mode setting), then the attacker may be able to cause the user to perform unintended actions by manipulating the cookie's value. If the cookie is used to track the user's session, then the attacker may be able to perform a session fixation attack, in which they set the cookie's value to a valid token that they have obtained from the application, and then hijack the session during the victim user's subsequent interaction with the application.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based cookie manipulation vulnerabilities is not to dynamically write to cookies using data that originated from any untrusted source. This behavior should never be implemented for cookies that have any role in controlling privileged actions or user sessions within the application.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cookie manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/cookie-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-565: Reliance on Cookies without Validation and Integrity Checking"#, url: r#"https://cwe.mitre.org/data/definitions/565.html"# },
            Classification { title: r#"CWE-829: Inclusion of Functionality from Untrusted Control Sphere"#, url: r#"https://cwe.mitre.org/data/definitions/829.html"# },
            Classification { title: r#"CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies"#, url: r#"https://capec.mitre.org/data/definitions/31.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245698,
        declared_type_index: 5245698,
        name: r#"Cookie manipulation (stored DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>DOM-based cookie manipulation arises when a  script writes controllable data into the value of a cookie. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will set an arbitrary value in the user's cookie.</p>
<p>The potential impact of the vulnerability depends on the role that the cookie plays within the application. If the cookie is used to control the behavior that results from certain user actions (for example, a 'production' versus 'demo' mode setting), then the attacker may be able to cause the user to perform unintended actions by manipulating the cookie's value. If the cookie is used to track the user's session, then the attacker may be able to perform a session fixation attack, in which they set the cookie's value to a valid token that they have obtained from the application, and then hijack the session during the victim user's subsequent interaction with the application.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based cookie manipulation vulnerabilities is not to dynamically write to cookies using data that originated from any untrusted source. This behavior should never be implemented for cookies that have any role in controlling privileged actions or user sessions within the application.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cookie manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/cookie-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-565: Reliance on Cookies without Validation and Integrity Checking"#, url: r#"https://cwe.mitre.org/data/definitions/565.html"# },
            Classification { title: r#"CWE-829: Inclusion of Functionality from Untrusted Control Sphere"#, url: r#"https://cwe.mitre.org/data/definitions/829.html"# },
            Classification { title: r#"CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies"#, url: r#"https://capec.mitre.org/data/definitions/31.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245952,
        declared_type_index: 5245952,
        name: r#"Ajax request header manipulation (DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>
<p>Ajax request header manipulation  arises when a script writes controllable data into a header of an Ajax request that is issued using XmlHttpRequest. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will set an arbitrary header in the subsequent Ajax request.</p>
<p>The potential impact of the vulnerability depends on the role of specific HTTP headers in the server-side application's processing of the Ajax request. If the header is used to control the behavior that results from the Ajax request, then the attacker may be able to cause the user to perform unintended actions by manipulating the header.</p>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based Ajax request header manipulation vulnerabilities is not to dynamically set Ajax request headers using data that originated from any untrusted source. This behavior should never be implemented for headers that have any role in controlling the effects of privileged actions within the application. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Ajax request header manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-6: Argument Injection"#, url: r#"https://capec.mitre.org/data/definitions/6.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245953,
        declared_type_index: 5245953,
        name: r#"Ajax request header manipulation (reflected DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>Ajax request header manipulation  arises when a script writes controllable data into a header of an Ajax request that is issued using XmlHttpRequest. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will set an arbitrary header in the subsequent Ajax request.</p>
<p>The potential impact of the vulnerability depends on the role of specific HTTP headers in the server-side application's processing of the Ajax request. If the header is used to control the behavior that results from the Ajax request, then the attacker may be able to cause the user to perform unintended actions by manipulating the header.</p>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based Ajax request header manipulation vulnerabilities is not to dynamically set Ajax request headers using data that originated from any untrusted source. This behavior should never be implemented for headers that have any role in controlling the effects of privileged actions within the application. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Ajax request header manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-6: Argument Injection"#, url: r#"https://capec.mitre.org/data/definitions/6.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5245954,
        declared_type_index: 5245954,
        name: r#"Ajax request header manipulation (stored DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>Ajax request header manipulation  arises when a script writes controllable data into a header of an Ajax request that is issued using XmlHttpRequest. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will set an arbitrary header in the subsequent Ajax request.</p>
<p>The potential impact of the vulnerability depends on the role of specific HTTP headers in the server-side application's processing of the Ajax request. If the header is used to control the behavior that results from the Ajax request, then the attacker may be able to cause the user to perform unintended actions by manipulating the header.</p>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based Ajax request header manipulation vulnerabilities is not to dynamically set Ajax request headers using data that originated from any untrusted source. This behavior should never be implemented for headers that have any role in controlling the effects of privileged actions within the application. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Ajax request header manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-116: Improper Encoding or Escaping of Output"#, url: r#"https://cwe.mitre.org/data/definitions/116.html"# },
            Classification { title: r#"CAPEC-6: Argument Injection"#, url: r#"https://capec.mitre.org/data/definitions/6.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246208,
        declared_type_index: 5246208,
        name: r#"Denial of service (DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>

<p>DOM-based denial of service  arises when a script passes controllable data to a problematic platform API in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause a denial of service condition on the user's computer when the relevant API is invoked. Depending on the nature of the API, the invocation may cause the user's computer to consume excessive amounts of CPU or disk space. This may result in side effects if the web browser restricts application functionality; for example, by rejecting attempts to store data in localStorage or killing busy scripts.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based denial of service vulnerabilities is not to dynamically pass data into problematic platform APIs that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from causing a denial of service condition. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Denial of service (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/denial-of-service"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')"#, url: r#"https://cwe.mitre.org/data/definitions/400.html"# },
            Classification { title: r#"CAPEC-125: Flooding"#, url: r#"https://capec.mitre.org/data/definitions/125.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246209,
        declared_type_index: 5246209,
        name: r#"Denial of service (reflected DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>DOM-based denial of service  arises when a script passes controllable data to a problematic platform API in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause a denial of service condition on the user's computer when the relevant API is invoked. Depending on the nature of the API, the invocation may cause the user's computer to consume excessive amounts of CPU or disk space. This may result in side effects if the web browser restricts application functionality; for example, by rejecting attempts to store data in localStorage or killing busy scripts.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based denial of service vulnerabilities is not to dynamically pass data into problematic platform APIs that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from causing a denial of service condition. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Denial of service (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/denial-of-service"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')"#, url: r#"https://cwe.mitre.org/data/definitions/400.html"# },
            Classification { title: r#"CAPEC-125: Flooding"#, url: r#"https://capec.mitre.org/data/definitions/125.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246210,
        declared_type_index: 5246210,
        name: r#"Denial of service (stored DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>DOM-based denial of service  arises when a script passes controllable data to a problematic platform API in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause a denial of service condition on the user's computer when the relevant API is invoked. Depending on the nature of the API, the invocation may cause the user's computer to consume excessive amounts of CPU or disk space. This may result in side effects if the web browser restricts application functionality; for example, by rejecting attempts to store data in localStorage or killing busy scripts.</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based denial of service vulnerabilities is not to dynamically pass data into problematic platform APIs that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from causing a denial of service condition. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Denial of service (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/denial-of-service"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')"#, url: r#"https://cwe.mitre.org/data/definitions/400.html"# },
            Classification { title: r#"CAPEC-125: Flooding"#, url: r#"https://capec.mitre.org/data/definitions/125.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246464,
        declared_type_index: 5246464,
        name: r#"HTML5 web message manipulation (DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>
<p>HTML5 web message manipulation arises when a script sends controllable data as a web message to another document within the browser. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to send a web message containing data that is under the attacker's control.</p>
<p>The potential impact of the vulnerability depends on the destination document's handling of the incoming message. If the destination document trusts the sender not to transmit malicious data in the message, and handles the data in an unsafe manner, then the joint behavior of the two documents may allow an attacker to compromise the application user.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based HTML5 web message manipulation vulnerabilities is not to send a web message containing data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from compromising the user. This validation can be carried out by the document that sends the message, or by the document that receives the message, or both, depending on the trust relationship between the two documents.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Web message manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/web-message-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246465,
        declared_type_index: 5246465,
        name: r#"HTML5 web message manipulation (reflected DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>HTML5 web message manipulation arises when a script sends controllable data as a web message to another document within the browser. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to send a web message containing data that is under the attacker's control.</p>
<p>The potential impact of the vulnerability depends on the destination document's handling of the incoming message. If the destination document trusts the sender not to transmit malicious data in the message, and handles the data in an unsafe manner, then the joint behavior of the two documents may allow an attacker to compromise the application user.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based HTML5 web message manipulation vulnerabilities is not to send a web message containing data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from compromising the user. This validation can be carried out by the document that sends the message, or by the document that receives the message, or both, depending on the trust relationship between the two documents.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Web message manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/web-message-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246466,
        declared_type_index: 5246466,
        name: r#"HTML5 web message manipulation (stored DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>HTML5 web message manipulation arises when a script sends controllable data as a web message to another document within the browser. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the user's browser to send a web message containing data that is under the attacker's control.</p>
<p>The potential impact of the vulnerability depends on the destination document's handling of the incoming message. If the destination document trusts the sender not to transmit malicious data in the message, and handles the data in an unsafe manner, then the joint behavior of the two documents may allow an attacker to compromise the application user.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based HTML5 web message manipulation vulnerabilities is not to send a web message containing data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from compromising the user. This validation can be carried out by the document that sends the message, or by the document that receives the message, or both, depending on the trust relationship between the two documents.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Web message manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/web-message-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246720,
        declared_type_index: 5246720,
        name: r#"HTML5 storage manipulation (DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>
<p>HTML5 storage manipulation arises when a script stores controllable data in the HTML5 storage of the web browser (either localStorage or sessionStorage). An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause the user's browser to store attacker-controllable data.</p>
<p>This behavior does not in itself constitute a security vulnerability. However, if the application later reads the data back from storage and processes it in an unsafe way, then an attacker may be able to leverage the storage mechanism to deliver other DOM-based attacks, such as cross-site scripting and JavaScript injection.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based HTML5 storage manipulation is not to place in HTML5 storage any data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from being stored.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: HTML5 storage manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/html5-storage-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246721,
        declared_type_index: 5246721,
        name: r#"HTML5 storage manipulation (reflected DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>HTML5 storage manipulation arises when a script stores controllable data in the HTML5 storage of the web browser (either localStorage or sessionStorage). An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause the user's browser to store attacker-controllable data.</p>
<p>This behavior does not in itself constitute a security vulnerability. However, if the application later reads the data back from storage and processes it in an unsafe way, then an attacker may be able to leverage the storage mechanism to deliver other DOM-based attacks, such as cross-site scripting and JavaScript injection.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based HTML5 storage manipulation is not to place in HTML5 storage any data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from being stored.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: HTML5 storage manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/html5-storage-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246722,
        declared_type_index: 5246722,
        name: r#"HTML5 storage manipulation (stored DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>HTML5 storage manipulation arises when a script stores controllable data in the HTML5 storage of the web browser (either localStorage or sessionStorage). An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will cause the user's browser to store attacker-controllable data.</p>
<p>This behavior does not in itself constitute a security vulnerability. However, if the application later reads the data back from storage and processes it in an unsafe way, then an attacker may be able to leverage the storage mechanism to deliver other DOM-based attacks, such as cross-site scripting and JavaScript injection.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based HTML5 storage manipulation is not to place in HTML5 storage any data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from being stored.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: HTML5 storage manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/html5-storage-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246976,
        declared_type_index: 5246976,
        name: r#"Link manipulation (DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>
<p>DOM-based link manipulation  arises when a script writes controllable data to a navigation target within the current page, such as a clickable link or the submission URL of a form. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will modify the target of links within the response. An attacker may be able to leverage this to perform various attacks, including:</p>
<ul>
<li>Causing the user to redirect to an arbitrary external URL, to facilitate a phishing attack.</li><li>Causing the user to submit sensitive form data to a server controlled by the attacker.</li><li>Causing the user to perform an unintended action within the application, by changing the file or query string associated with a link.</li><li>Bypassing browser anti-XSS defenses by injecting on-site links containing XSS exploits, since browser anti-XSS defenses typically do not operate on on-site links.</li></ul>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based link manipulation vulnerabilities is not to dynamically set the target URLs of links or forms using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a link target. In general, this is best achieved by using a whitelist of URLs that are permitted link targets, and strictly validating the target against this list before setting the link target.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Link manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/link-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246977,
        declared_type_index: 5246977,
        name: r#"Link manipulation (reflected DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM-based link manipulation  arises when a script writes controllable data to a navigation target within the current page, such as a clickable link or the submission URL of a form. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will modify the target of links within the response. An attacker may be able to leverage this to perform various attacks, including:</p>
<ul>
<li>Causing the user to redirect to an arbitrary external URL, to facilitate a phishing attack.</li><li>Causing the user to submit sensitive form data to a server controlled by the attacker.</li><li>Causing the user to perform an unintended action within the application, by changing the file or query string associated with a link.</li><li>Bypassing browser anti-XSS defenses by injecting on-site links containing XSS exploits, since browser anti-XSS defenses typically do not operate on on-site links.</li></ul>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based link manipulation vulnerabilities is not to dynamically set the target URLs of links or forms using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a link target. In general, this is best achieved by using a whitelist of URLs that are permitted link targets, and strictly validating the target against this list before setting the link target.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Link manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/link-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246978,
        declared_type_index: 5246978,
        name: r#"Link manipulation (stored DOM-based)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM-based link manipulation  arises when a script writes controllable data to a navigation target within the current page, such as a clickable link or the submission URL of a form. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will modify the target of links within the response. An attacker may be able to leverage this to perform various attacks, including:</p>
<ul>
<li>Causing the user to redirect to an arbitrary external URL, to facilitate a phishing attack.</li><li>Causing the user to submit sensitive form data to a server controlled by the attacker.</li><li>Causing the user to perform an unintended action within the application, by changing the file or query string associated with a link.</li><li>Bypassing browser anti-XSS defenses by injecting on-site links containing XSS exploits, since browser anti-XSS defenses typically do not operate on on-site links.</li></ul>
<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based link manipulation vulnerabilities is not to dynamically set the target URLs of links or forms using data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing an arbitrary URL as a link target. In general, this is best achieved by using a whitelist of URLs that are permitted link targets, and strictly validating the target against this list before setting the link target.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Link manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/link-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246979,
        declared_type_index: 5246979,
        name: r#"Link manipulation (reflected)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Link manipulation occurs when an application embeds user input into the path or domain of URLs that appear within application responses.&nbsp;An attacker can use this vulnerability to construct a link that, if visited by another application user, will modify the target of URLs within the response. It may be possible to leverage this to perform various attacks, such as:</p>
<ul>
  <li>Manipulating the path of an on-site link that has sensitive parameters in the URL. If the response from the modified path contains references to off-site resources, then the sensitive data might be leaked to external domains via the Referer header.</li>
  <li>Manipulating the URL targeted by a form action, making the form submission have unintended side effects.</li>
  <li>Manipulating the URL used by a CSS import statement to point to an attacker-uploaded file, resulting in CSS injection.</li>
  <li>Injecting on-site links containing XSS exploits, thereby bypassing browser anti-XSS defenses, since those defenses typically do not operate on on-site links.</li>
</ul>
<p>The security impact of this issue depends largely on the nature of the application functionality. Even if it has no direct impact on its own, an attacker may use it in conjunction with other vulnerabilities to escalate their overall severity.</p>"#,
        remediation: Some(r#"<p>Consider using a whitelist to restrict user input to safe values. Please note that in some situations this issue will have no security impact, meaning no remediation is necessary.</p>"#),
        references: &[
            Reference { title: r#"Using path manipulation to hijack Flickr accounts"#, url: r#"https://mishresec.wordpress.com/2017/10/13/yahoo-bug-bounty-chaining-3-minor-issues-to-takeover-flickr-accounts/"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5246980,
        declared_type_index: 5246980,
        name: r#"Link manipulation (stored)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Link manipulation occurs when an application embeds user input into the path or domain of URLs that appear within application responses.&nbsp;An attacker can use this vulnerability to construct a link that, if visited by another application user, will modify the target of URLs within the response. It may be possible to leverage this to perform various attacks, such as:</p>
<ul>
  <li>Manipulating the path of an on-site link that has sensitive parameters in the URL. If the response from the modified path contains references to off-site resources, then the sensitive data might be leaked to external domains via the Referer header.</li>
  <li>Manipulating the URL targeted by a form action, making the form submission have unintended side effects.</li>
  <li>Manipulating the URL used by a CSS import statement to point to an attacker-uploaded file, resulting in CSS injection.</li>
  <li>Injecting on-site links containing XSS exploits, thereby bypassing browser anti-XSS defenses, since those defenses typically do not operate on on-site links.</li>
</ul>
<p>The security impact of this issue depends largely on the nature of the application functionality. Even if it has no direct impact on its own, an attacker may use it in conjunction with other vulnerabilities to escalate their overall severity.</p>

<p>Stored link manipulation vulnerabilities arise when the applicable input was submitted in an previous request and stored by the application.</p>"#,
        remediation: Some(r#"<p>Consider using a whitelist to restrict user input to safe values. Please note that in some situations this issue will have no security impact, meaning no remediation is necessary.</p>"#),
        references: &[
            Reference { title: r#"Using path manipulation to hijack Flickr accounts"#, url: r#"https://mishresec.wordpress.com/2017/10/13/yahoo-bug-bounty-chaining-3-minor-issues-to-takeover-flickr-accounts/"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5247232,
        declared_type_index: 5247232,
        name: r#"Document domain manipulation (DOM-based)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>

<p>Document domain manipulation arises when a script uses controllable data to set the document.domain property. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the response page to set an arbitrary document.domain value.</p>
<p>The document.domain property is used by browsers in their enforcement of the same origin policy. If two pages from different origins explicitly set the same document.domain value, then those two pages can interact in unrestricted ways. If an attacker can cause a page of a targeted application, and another page they control (either directly, or via an XSS-like vulnerability), to set the same document.domain value, then the attacker may be able to fully compromise the targeted application page via the page they already control, with the same possibilities for exploitation as regular cross-site scripting (XSS) vulnerabilities.</p>
<p>Browsers generally enforce some restrictions on the values that can be assigned to document.domain, and may prevent the use of completely different values than the actual origin of the page. However, there are two important caveats to this. Firstly, browsers allow the use of child or parent domains, so an attacker may be able to switch the domain of the targeted application page to that of a related application with a weaker security posture. Secondly, some browser quirks enable switching to completely unrelated domains. These caveats mean that the ability to manipulate the document.domain property of a page generally represents a security vulnerability whose severity is not far behind regular XSS.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based document domain manipulation vulnerabilities is not to dynamically set the document.domain property using data that originated from any untrusted source. If it is necessary to programmatically set the document.domain property from within client-side code, then the application should employ a set list of acceptable values, and assign only from values in that list. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Document domain manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/document-domain-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5247233,
        declared_type_index: 5247233,
        name: r#"Document domain manipulation (reflected DOM-based)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>Document domain manipulation arises when a script uses controllable data to set the document.domain property. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the response page to set an arbitrary document.domain value.</p>
<p>The document.domain property is used by browsers in their enforcement of the same origin policy. If two pages from different origins explicitly set the same document.domain value, then those two pages can interact in unrestricted ways. If an attacker can cause a page of a targeted application, and another page they control (either directly, or via an XSS-like vulnerability), to set the same document.domain value, then the attacker may be able to fully compromise the targeted application page via the page they already control, with the same possibilities for exploitation as regular cross-site scripting (XSS) vulnerabilities.</p>
<p>Browsers generally enforce some restrictions on the values that can be assigned to document.domain, and may prevent the use of completely different values than the actual origin of the page. However, there are two important caveats to this. Firstly, browsers allow the use of child or parent domains, so an attacker may be able to switch the domain of the targeted application page to that of a related application with a weaker security posture. Secondly, some browser quirks enable switching to completely unrelated domains. These caveats mean that the ability to manipulate the document.domain property of a page generally represents a security vulnerability whose severity is not far behind regular XSS.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based document domain manipulation vulnerabilities is not to dynamically set the document.domain property using data that originated from any untrusted source. If it is necessary to programmatically set the document.domain property from within client-side code, then the application should employ a set list of acceptable values, and assign only from values in that list. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Document domain manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/document-domain-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5247234,
        declared_type_index: 5247234,
        name: r#"Document domain manipulation (stored DOM-based)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>

<p>Document domain manipulation arises when a script uses controllable data to set the document.domain property. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause the response page to set an arbitrary document.domain value.</p>
<p>The document.domain property is used by browsers in their enforcement of the same origin policy. If two pages from different origins explicitly set the same document.domain value, then those two pages can interact in unrestricted ways. If an attacker can cause a page of a targeted application, and another page they control (either directly, or via an XSS-like vulnerability), to set the same document.domain value, then the attacker may be able to fully compromise the targeted application page via the page they already control, with the same possibilities for exploitation as regular cross-site scripting (XSS) vulnerabilities.</p>
<p>Browsers generally enforce some restrictions on the values that can be assigned to document.domain, and may prevent the use of completely different values than the actual origin of the page. However, there are two important caveats to this. Firstly, browsers allow the use of child or parent domains, so an attacker may be able to switch the domain of the targeted application page to that of a related application with a weaker security posture. Secondly, some browser quirks enable switching to completely unrelated domains. These caveats mean that the ability to manipulate the document.domain property of a page generally represents a security vulnerability whose severity is not far behind regular XSS.
</p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based document domain manipulation vulnerabilities is not to dynamically set the document.domain property using data that originated from any untrusted source. If it is necessary to programmatically set the document.domain property from within client-side code, then the application should employ a set list of acceptable values, and assign only from values in that list. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Document domain manipulation (DOM-based)"#, url: r#"https://portswigger.net/web-security/dom-based/document-domain-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5247488,
        declared_type_index: 5247488,
        name: r#"DOM data manipulation (DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.</p>
<p>DOM data manipulation arises when a script writes controllable data to a field within the DOM that is used within the visible UI or client-side application logic. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will modify the appearance or behavior of the client-side UI. An attacker may be able to leverage this to perform virtual defacement of the application, or possibly to induce the user to perform unintended actions. </p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based DOM data manipulation vulnerabilities is not to dynamically write to DOM data fields any data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from being stored. In general, this is best achieved by using a whitelist of permitted values.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: DOM data manipulation"#, url: r#"https://portswigger.net/web-security/dom-based/dom-data-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5247489,
        declared_type_index: 5247489,
        name: r#"DOM data manipulation (reflected DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Reflected DOM-based vulnerabilities arise when data is copied from a request and echoed into the application's immediate response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the reflection to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM data manipulation arises when a script writes controllable data to a field within the DOM that is used within the visible UI or client-side application logic. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will modify the appearance or behavior of the client-side UI. An attacker may be able to leverage this to perform virtual defacement of the application, or possibly to induce the user to perform unintended actions. </p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based DOM data manipulation vulnerabilities is not to dynamically write to DOM data fields any data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from being stored. In general, this is best achieved by using a whitelist of permitted values.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: DOM data manipulation"#, url: r#"https://portswigger.net/web-security/dom-based/dom-data-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5247490,
        declared_type_index: 5247490,
        name: r#"DOM data manipulation (stored DOM-based)"#,
        typical_severity: Severity::Info,
        description: r#"<p>Stored DOM-based vulnerabilities arise when user input is stored and later embedded into a response within a part of the DOM that is then processed in an unsafe way by a client-side script. An attacker can leverage the data storage to control a part of the response (for example, a JavaScript string) that can be used to trigger the DOM-based vulnerability.</p>
<p>DOM data manipulation arises when a script writes controllable data to a field within the DOM that is used within the visible UI or client-side application logic. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will modify the appearance or behavior of the client-side UI. An attacker may be able to leverage this to perform virtual defacement of the application, or possibly to induce the user to perform unintended actions. </p>

<p>Burp Suite automatically identifies this issue using dynamic and static code analysis. Static analysis can lead to false positives that are not actually exploitable. If Burp Scanner has not provided any evidence resulting from dynamic analysis, you should review the relevant code and execution paths  to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation.</p>"#,
        remediation: Some(r#"<p>The most effective way to avoid DOM-based DOM data manipulation vulnerabilities is not to dynamically write to DOM data fields any data that originated from any untrusted source. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from being stored. In general, this is best achieved by using a whitelist of permitted values.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: DOM data manipulation"#, url: r#"https://portswigger.net/web-security/dom-based/dom-data-manipulation"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5247744,
        declared_type_index: 5247744,
        name: r#"CSS injection (reflected)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>CSS injection vulnerabilities arise when an application imports a style sheet from a user-supplied URL, or embeds user input in CSS blocks without adequate escaping. They are closely related to cross-site scripting (XSS) vulnerabilities but often trickier to exploit. </p>
<p>Being able to inject arbitrary CSS into the victim's browser may enable various attacks, including:</p>
<ul>
  <li>Executing arbitrary JavaScript using IE's expression() function.</li><li>Using CSS selectors to read parts of the HTML source, which may include sensitive data such as anti-CSRF tokens.</li>
<li>Capturing any sensitive data within the URL query string by making a further style sheet import to a URL on the attacker's domain, and monitoring the incoming Referer header.</li></ul>"#,
        remediation: Some(r#"<p>Ensure that user input is adequately escaped before embedding it in CSS blocks, and consider using a whitelist to prevent loading of arbitrary style sheets.</p>"#),
        references: &[
            Reference { title: r#"Malicious CSS"#, url: r#"https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities#badcss"# },
            Reference { title: r#"Abusing unicode-range of @font-face"#, url: r#"http://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-468: Generic Cross-Browser Cross-Domain Theft"#, url: r#"https://capec.mitre.org/data/definitions/468.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5247745,
        declared_type_index: 5247745,
        name: r#"CSS injection (stored)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>CSS injection vulnerabilities arise when an application imports a style sheet from a user-supplied URL, or embeds user input in CSS blocks without adequate escaping. They are closely related to cross-site scripting (XSS) vulnerabilities but often trickier to exploit. </p>
<p>Being able to inject arbitrary CSS into the victim's browser may enable various attacks, including:</p>
<ul>
  <li>Executing arbitrary JavaScript using IE's expression() function.</li><li>Using CSS selectors to read parts of the HTML source, which may include sensitive data such as anti-CSRF tokens.</li>
<li>Capturing any sensitive data within the URL query string by making a further style sheet import to a URL on the attacker's domain, and monitoring the incoming Referer header.</li></ul><p>Stored CSS injection vulnerabilities arise when the applicable input was submitted in an previous request and stored by the application.</p>"#,
        remediation: Some(r#"<p>Ensure that user input is adequately escaped before embedding it in CSS blocks, and consider using a whitelist to prevent loading of arbitrary style sheets.</p>"#),
        references: &[
            Reference { title: r#"Malicious CSS"#, url: r#"https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities#badcss"# },
            Reference { title: r#"Abusing unicode-range of @font-face"#, url: r#"http://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-468: Generic Cross-Browser Cross-Domain Theft"#, url: r#"https://capec.mitre.org/data/definitions/468.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5248000,
        declared_type_index: 5248000,
        name: r#"Client-side HTTP parameter pollution (reflected)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Client-side HTTP parameter pollution (HPP) vulnerabilities arise when an application embeds user input in URLs in an unsafe manner.  An attacker can use this vulnerability to construct a URL that, if visited by another application user, will modify URLs within the response by inserting additional query string parameters and sometimes overriding existing ones. This may result in links and forms having unexpected side effects. For example, it may be possible to modify an invitation form using HPP so that the invitation is delivered to an unexpected recipient. </p>
<p>The security impact of this issue depends largely on the nature of the application functionality. Even if it has no direct impact on its own, an attacker may use it in conjunction with other vulnerabilities to escalate their overall severity.</p>"#,
        remediation: Some(r#"<p>Ensure that user input is URL-encoded before it is embedded in a URL.</p>"#),
        references: &[
            Reference { title: r#"HTTP Parameter Pollution"#, url: r#"https://wiki.owasp.org/images/b/ba/AppsecEU09_CarettoniDiPaola_v0.8.pdf"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-233: Improper Handling of Parameters"#, url: r#"https://cwe.mitre.org/data/definitions/233.html"# },
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-460: HTTP Parameter Pollution (HPP)"#, url: r#"https://capec.mitre.org/data/definitions/460.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5248001,
        declared_type_index: 5248001,
        name: r#"Client-side HTTP parameter pollution (stored)"#,
        typical_severity: Severity::Low,
        description: r#"<p>Client-side HTTP parameter pollution (HPP) vulnerabilities arise when an application embeds user input in URLs in an unsafe manner.  An attacker can use this vulnerability to construct a URL that, if visited by another application user, will modify URLs within the response by inserting additional query string parameters and sometimes overriding existing ones. This may result in links and forms having unexpected side effects. For example, it may be possible to modify an invitation form using HPP so that the invitation is delivered to an unexpected recipient. </p>
<p>The security impact of this issue depends largely on the nature of the application functionality. Even if it has no direct impact on its own, an attacker may use it in conjunction with other vulnerabilities to escalate their overall severity.</p>

<p>Stored client-side HTTP parameter pollution vulnerabilities arise when the applicable input was submitted in an previous request and stored by the application.</p>"#,
        remediation: Some(r#"<p>Ensure that user input is URL-encoded before it is embedded in a URL.</p>"#),
        references: &[
            Reference { title: r#"HTTP Parameter Pollution"#, url: r#"https://wiki.owasp.org/images/b/ba/AppsecEU09_CarettoniDiPaola_v0.8.pdf"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-233: Improper Handling of Parameters"#, url: r#"https://cwe.mitre.org/data/definitions/233.html"# },
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-460: HTTP Parameter Pollution (HPP)"#, url: r#"https://capec.mitre.org/data/definitions/460.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5248256,
        declared_type_index: 5248256,
        name: r#"Form action hijacking (reflected)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Form action hijacking vulnerabilities arise when an application places user-supplied input into the action URL of an HTML form. An attacker can use this vulnerability to construct a URL that, if visited by another application user, will modify the action URL of a form to point to the attacker's server. If a user submits the form then its contents, including any input from the victim user, will be delivered directly to the attacker.</p>
<p> Even if the user doesn't enter any sensitive information, the form may still deliver a valid CSRF token to the attacker, enabling them to perform CSRF attacks. In some cases web browsers may help exacerbate this issue by autocompleting forms with previously entered user input. </p>"#,
        remediation: Some(r#"<p>Consider hard-coding the form action URL, or implementing a whitelist of allowed values.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 5248257,
        declared_type_index: 5248257,
        name: r#"Form action hijacking (stored)"#,
        typical_severity: Severity::Medium,
        description: r#"<p>Form action hijacking vulnerabilities arise when an application places user-supplied input into the action URL of an HTML form. An attacker can use this vulnerability to construct a URL that, if visited by another application user, will modify the action URL of a form to point to the attacker's server. If a user submits the form then its contents, including any input from the victim user, will be delivered directly to the attacker.</p>
<p> Even if the user doesn't enter any sensitive information, the form may still deliver a valid CSRF token to the attacker, enabling them to perform CSRF attacks. In some cases web browsers may help exacerbate this issue by autocompleting forms with previously entered user input. </p>

<p>Stored form action hijacking vulnerabilities arise when the applicable input was submitted in an previous request and stored by the application.</p>"#,
        remediation: Some(r#"<p>Consider hard-coding the form action URL, or implementing a whitelist of allowed values.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-73: External Control of File Name or Path"#, url: r#"https://cwe.mitre.org/data/definitions/73.html"# },
            Classification { title: r#"CWE-20: Improper Input Validation"#, url: r#"https://cwe.mitre.org/data/definitions/20.html"# },
            Classification { title: r#"CAPEC-153: Input Data Manipulation"#, url: r#"https://capec.mitre.org/data/definitions/153.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6291584,
        declared_type_index: 6291584,
        name: r#"Database connection string disclosed"#,
        typical_severity: Severity::Medium,
        description: r#"<p>A database connection string specifies information about a data source and the means of connecting to it. In web applications, connection strings are generally used by the application tier to connect to the back database used for storing application data. They are usually read from server-side configuration files or hard-coded into application source code.</p>"#,
        remediation: Some(r#"<p>It is almost never necessary for applications to disclose database connection strings to clients. The reason for the disclosure should be reviewed and addressed.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-15: External Control of System or Configuration Setting"#, url: r#"https://cwe.mitre.org/data/definitions/15.html"# },
            Classification { title: r#"CWE-497: Exposure of System Data to an Unauthorized Control Sphere"#, url: r#"https://cwe.mitre.org/data/definitions/497.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6291632,
        declared_type_index: 6291632,
        name: r#"Source code disclosure"#,
        typical_severity: Severity::Low,
        description: r#"<p>Source code intended to be kept server-side can sometimes end up being disclosed to users. Such code may contain sensitive information such as database passwords and secret keys, which may help malicious users formulate attacks against the application.</p>"#,
        remediation: Some(r#"<p>Server-side source code is normally disclosed to clients as a result of typographical errors in scripts or because of misconfiguration, such as failing to grant executable permissions to a script or directory. Review the cause of the code disclosure and prevent it from happening.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-18: Source Code"#, url: r#"https://cwe.mitre.org/data/definitions/18.html"# },
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
            Classification { title: r#"CWE-388: Error Handling"#, url: r#"https://cwe.mitre.org/data/definitions/388.html"# },
            Classification { title: r#"CWE-540: Information Exposure Through Source Code"#, url: r#"https://cwe.mitre.org/data/definitions/540.html"# },
            Classification { title: r#"CWE-541: Information Exposure Through Include Source Code"#, url: r#"https://cwe.mitre.org/data/definitions/541.html"# },
            Classification { title: r#"CWE-615: Information Exposure Through Comments"#, url: r#"https://cwe.mitre.org/data/definitions/615.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6291672,
        declared_type_index: 6291672,
        name: r#"Backup file"#,
        typical_severity: Severity::Info,
        description: r#"<p>Publicly accessible backups and outdated copies of files can provide attackers with extra attack surface. Depending on the server configuration and file type, they may also expose source code, configuration details, and other information intended to remain secret.</p>"#,
        remediation: Some(r#"<p>Review the file to identify whether it's intended to be publicly accessible, and remove it from the server's web root if it isn't. It may also be worth auditing the server contents to find other outdated files, and taking measures to prevent the problem from reoccurring. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure via backup files"#, url: r#"https://portswigger.net/web-security/information-disclosure/exploiting#source-code-disclosure-via-backup-files"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-530: Exposure of Backup File to an Unauthorized Control Sphere"#, url: r#"https://cwe.mitre.org/data/definitions/530.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
            Classification { title: r#"CAPEC-204: Lifting Sensitive Data Embedded in Cache"#, url: r#"https://capec.mitre.org/data/definitions/204.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6291712,
        declared_type_index: 6291712,
        name: r#"Directory listing"#,
        typical_severity: Severity::Info,
        description: r#"<p>Web servers can be configured to automatically list the contents of directories that do not have an index page present. This can aid an attacker by enabling them to quickly identify the resources at a given path, and proceed directly to analyzing and attacking those resources. It particularly increases the exposure of sensitive files within the directory that are not intended to be accessible to users, such as temporary files and crash dumps.</p>
<p>Directory listings themselves do not necessarily constitute a security vulnerability. Any sensitive resources within the web root should in any case be properly access-controlled, and should not be accessible by an unauthorized party who happens to know or guess the URL. Even when directory listings are disabled, an attacker may guess the location of sensitive files using automated tools.</p>"#,
        remediation: Some(r#"<p>There is not usually any good reason to provide directory listings, and disabling them may place additional hurdles in the path of an attacker. This can normally be achieved in two ways:</p>
<ul>
<li>Configure your web server to prevent directory listings for all paths beneath the web root; </li>
<li>Place into each directory a default file (such as index.htm) that the web server will display instead of returning a directory listing.</li></ul>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure via directory listings"#, url: r#"https://portswigger.net/web-security/information-disclosure/exploiting#directory-listings"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-538: File and Directory Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/538.html"# },
            Classification { title: r#"CWE-548: Information Exposure Through Directory Listing"#, url: r#"https://cwe.mitre.org/data/definitions/548.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6291968,
        declared_type_index: 6291968,
        name: r#"Email addresses disclosed"#,
        typical_severity: Severity::Info,
        description: r#"<p>The presence of email addresses within application responses does not necessarily constitute a security vulnerability. Email addresses may appear intentionally within contact information, and many applications (such as web mail) include arbitrary third-party email addresses within their core content.</p>
<p>However, email addresses of developers and other individuals (whether appearing on-screen or hidden within page source) may disclose information that is useful to an attacker; for example, they may represent usernames that can be used at the application's login, and they may be used in social engineering attacks against the organization's personnel. Unnecessary or excessive disclosure of email addresses may also lead to an increase in the volume of spam email received.</p>"#,
        remediation: Some(r#"<p>Consider removing any email addresses that are unnecessary, or replacing personal addresses with anonymous mailbox addresses (such as helpdesk@example.com).</p>
<p>To reduce the quantity of spam sent to anonymous mailbox addresses, consider hiding the email address and instead providing a form that generates the email server-side, protected by a CAPTCHA if necessary. </p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6292224,
        declared_type_index: 6292224,
        name: r#"Private IP addresses disclosed"#,
        typical_severity: Severity::Info,
        description: r#"<p>RFC 1918 specifies ranges of IP addresses that are reserved for use in private networks and cannot be routed on the public Internet. Although various methods exist by which an attacker can determine the public IP addresses in use by an organization, the private addresses used internally cannot usually be determined in the same ways.</p>
<p>Discovering the private addresses used within an organization can help an attacker in carrying out network-layer attacks aiming to penetrate the organization's internal infrastructure. </p>"#,
        remediation: Some(r#"<p>There is not usually any good reason to disclose the internal IP addresses used within an organization's infrastructure. If these are being returned in service banners or debug messages, then the relevant services should be configured to mask the private addresses. If they are being used to track back-end servers for load balancing purposes, then the addresses should be rewritten with innocuous identifiers from which an attacker cannot infer any useful information about the infrastructure.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6292480,
        declared_type_index: 6292480,
        name: r#"Social security numbers disclosed"#,
        typical_severity: Severity::Info,
        description: r#"<p>Applications sometimes disclose sensitive personal information such as social security numbers. Responses containing social security numbers may not represent any security vulnerability - for example, a number may belong to the logged-in user to whom it is displayed. If a social security number is identified during a security assessment it should be verified, then application logic reviewed to identify whether its disclosure within the application is necessary and appropriate.</p>"#,
        remediation: None,
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6292736,
        declared_type_index: 6292736,
        name: r#"Credit card numbers disclosed"#,
        typical_severity: Severity::Info,
        description: r#"<p>Applications sometimes disclose sensitive financial information such as credit card numbers. Responses containing credit card numbers may not represent any security vulnerability - for example, a number may belong to the logged-in user to whom it is displayed. If a credit card number is identified during a security assessment it should be verified, then application logic reviewed to identify whether its disclosure within the application is necessary and appropriate.</p>"#,
        remediation: None,
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
            Classification { title: r#"CWE-388: Error Handling"#, url: r#"https://cwe.mitre.org/data/definitions/312.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6292816,
        declared_type_index: 6292816,
        name: r#"Private key disclosed"#,
        typical_severity: Severity::Info,
        description: r#"<p>Disclosure of valid private keys may lead to unauthorized access to any systems that use them for authentication. Verify whether any keys disclosed are actually valid, and whether their disclosure within the application is appropriate.</p>"#,
        remediation: None,
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
            Classification { title: r#"CWE-388: Error Handling"#, url: r#"https://cwe.mitre.org/data/definitions/312.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
            Classification { title: r#"CAPEC-204: Lifting Sensitive Data Embedded in Cache"#, url: r#"https://capec.mitre.org/data/definitions/204.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6292992,
        declared_type_index: 6292992,
        name: r#"Robots.txt file"#,
        typical_severity: Severity::Info,
        description: r#"<p>The file robots.txt is used to give instructions to web robots, such as search engine crawlers, about locations within the web site that robots are allowed, or not allowed, to crawl and index.</p>
<p>The presence of the robots.txt does not in itself present any kind of security vulnerability. However, it is often used to identify restricted or private areas of a site's contents. The information in the file may therefore help an attacker to map out the site's contents, especially if some of the locations identified are not linked from elsewhere in the site. If the application relies on robots.txt to protect access to these areas, and does not enforce proper access control over them, then this presents a serious vulnerability.</p>"#,
        remediation: Some(r#"<p>The robots.txt file is not itself a security threat, and its correct use can represent good practice for non-security reasons. You should not assume that all web robots will honor the file's instructions. Rather, assume that attackers will pay close attention to any locations identified in the file. Do not rely on robots.txt to provide any kind of protection over unauthorized access.</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6293248,
        declared_type_index: 6293248,
        name: r#"Json Web Key Set disclosed"#,
        typical_severity: Severity::Info,
        description: r#"<p>
    A JSON Web Key Set is a JSON object that represents a set of JSON Web Keys (JWKs). Authorization servers often publish JWK Sets under well-known URLs to
    tell clients how they can verify the signature of issued JWTs. Defined in RFC 7517, this data structure contains cryptographic keys for different signature algorithms,
    such as HMAC or RSA for example. If a server is configured incorrectly, it may accidentally expose private key components as well as public ones.
    In this case, a malicious user could use any private keys they've obtained to tamper with the signature of JWT tokens and impersonate other users.
</p>

<p>
    Even if no secret key components are exposed, the knowledge of public keys may be useful for other attacks, such as algorithm and key confusion for example.
</p>"#,
        remediation: Some(r#"<p>
    If your JWK Set is exposed publicly, make sure to omit any private key components. As long as it only contains public key components, exposing a JWK Set
    is not a security threat in itself. In fact, its correct use can represent good practice for non-security reasons.
</p>"#),
        references: &[
            Reference { title: r#"JSON Web Key (JWK)"#, url: r#"https://datatracker.ietf.org/doc/html/rfc7517"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6293504,
        declared_type_index: 6293504,
        name: r#"JWT private key disclosed"#,
        typical_severity: Severity::High,
        description: r#"<p>
The JSON Web Signature specification defines the optional "jwk" header, which contains information about the key used to digitally sign the JWT.
Defined in RFC 7517, this data structure contains cryptographic keys for different signature algorithms, such as HMAC or RSA for example.
This parameter is particularly useful for servers that are configured to use multiple different keys because it can help to determine which key to use when verifying the signature.
</p>
<p>
If a server is configured incorrectly, it may accidentally include private key components into the "jwk" header parameter of JWTs that it issues.
In this case, a malicious user could use any private keys they've obtained to tamper with the signature of JWT tokens and impersonate other users.
</p>"#,
        remediation: Some(r#"<p>
If your JWK is embedded into the JWT header, make sure to omit any private key components.
As long as it only contains public key components, using the "jwk" header is not a security threat in itself.
In fact, its correct use can help servers to select a proper key for verification.
</p>"#),
        references: &[
            Reference { title: r#"JSON Web Key (JWK)"#, url: r#"https://datatracker.ietf.org/doc/html/rfc7517"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6293760,
        declared_type_index: 6293760,
        name: r#"OpenAPI definition found (active scan check)"#,
        typical_severity: Severity::Info,
        description: r#"<p>A publicly available OpenAPI definition was found.</p>
<p>An OpenAPI definition describes the structure of an HTTP-based API in YAML or JSON format, according to the OpenAPI specification. It enables humans to discover and understand the service's capabilities, and is also designed to be processed by software for automating tasks like API integration and validation.</p>
<p>A publicly-available OpenAPI definition does not necessarily present a security vulnerability. However, the API definition can be valuable to attackers as it may include information about the API structure, potentially enabling targeted attacks. For example it may include detailed explanations, examples, and usage scenarios.</p>"#,
        remediation: Some(r#"<p>Make sure that your API documentation only contains necessary information before you deploy it to production. This prevents attackers from using the definition to discover details about the API's available operations and other potentially sensitive information, including administrative functions.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Identifying API endpoints"#, url: r#"https://portswigger.net/web-security/api-testing#identifying-api-endpoints"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 6293761,
        declared_type_index: 6293761,
        name: r#"OpenAPI definition found (passive scan check)"#,
        typical_severity: Severity::Info,
        description: r#"<p>A publicly available OpenAPI definition was found.</p>
<p>An OpenAPI definition describes the structure of an HTTP-based API in YAML or JSON format, according to the OpenAPI specification. It enables humans to discover and understand the service's capabilities, and is also designed to be processed by software for automating tasks like API integration and validation.</p>
<p>A publicly-available OpenAPI definition does not necessarily present a security vulnerability. However, the API definition can be valuable to attackers as it may include information about the API structure, potentially enabling targeted attacks. For example it may include detailed explanations, examples, and usage scenarios.</p>"#,
        remediation: Some(r#"<p>Make sure that your API documentation only contains necessary information before you deploy it to production. This prevents attackers from using the definition to discover details about the API's available operations and other potentially sensitive information, including administrative functions.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Identifying API endpoints"#, url: r#"https://portswigger.net/web-security/api-testing#identifying-api-endpoints"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-200: Information Exposure"#, url: r#"https://cwe.mitre.org/data/definitions/200.html"# },
        ],
    },
    IssueDefinition {
        type_index: 7340288,
        declared_type_index: 7340288,
        name: r#"Cacheable HTTPS response"#,
        typical_severity: Severity::Info,
        description: r#"<p>Unless directed otherwise, browsers may store a local cached copy of content received from web servers. Some browsers, including Internet Explorer, cache content accessed via HTTPS. If sensitive information in application responses is stored in the local cache, then this may be retrieved by other users who have access to the same computer at a future time.</p>"#,
        remediation: Some(r#"<p>Applications should return caching directives instructing browsers not to store local copies of any sensitive data. Often, this can be achieved by configuring the web server to prevent caching for relevant paths within the web root. Alternatively, most web development platforms allow you to control the server's caching directives from within individual scripts. Ideally, the web server should return the following HTTP headers in all responses containing sensitive content:</p>
<ul>
<li>Cache-control: no-store</li><li>Pragma: no-cache</li></ul>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Information disclosure"#, url: r#"https://portswigger.net/web-security/information-disclosure"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-524: Information Exposure Through Caching"#, url: r#"https://cwe.mitre.org/data/definitions/524.html"# },
            Classification { title: r#"CWE-525: Information Exposure Through Browser Caching"#, url: r#"https://cwe.mitre.org/data/definitions/525.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 7340544,
        declared_type_index: 7340544,
        name: r#"Base64-encoded data in parameter"#,
        typical_severity: Severity::Info,
        description: r#"<p>Applications sometimes Base64-encode parameters in an attempt to obfuscate them from users or facilitate transport of binary data. The presence of Base64-encoded data may indicate security-sensitive information or functionality that is worthy of further investigation. The data should be reviewed to determine whether it contains any interesting information, or provides any additional entry points for malicious input.</p>"#,
        remediation: None,
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-310: Cryptographic Issues"#, url: r#"https://cwe.mitre.org/data/definitions/310.html"# },
            Classification { title: r#"CWE-311: Missing Encryption of Sensitive Data"#, url: r#"https://cwe.mitre.org/data/definitions/311.html"# },
            Classification { title: r#"CAPEC-37: Retrieve Embedded Sensitive Data"#, url: r#"https://capec.mitre.org/data/definitions/37.html"# },
        ],
    },
    IssueDefinition {
        type_index: 8388864,
        declared_type_index: 8388864,
        name: r#"Multiple content types specified"#,
        typical_severity: Severity::Info,
        description: r#"<p>If a  response specifies multiple incompatible content types, then the browser will usually analyze the response and attempt to determine the actual MIME type of its content. This can have unexpected results, and if the content contains any user-controllable data may lead to cross-site scripting or other client-side vulnerabilities.</p>
<p>In most cases, the presence of multiple incompatible content type statements does not constitute a security flaw, particularly if the response contains static content. You should review the contents of affected responses, and the context in which they appear, to determine whether any vulnerability exists. </p>"#,
        remediation: Some(r#"<p>For every response containing a message body, the application should include a single Content-type header that correctly and unambiguously states the MIME type of the content in the response body.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-436: Interpretation Conflict"#, url: r#"https://cwe.mitre.org/data/definitions/436.html"# },
            Classification { title: r#"CAPEC-63: Cross-Site Scripting (XSS)"#, url: r#"https://capec.mitre.org/data/definitions/63.html"# },
        ],
    },
    IssueDefinition {
        type_index: 8389120,
        declared_type_index: 8389120,
        name: r#"HTML does not specify charset"#,
        typical_severity: Severity::Info,
        description: r#"<p>If a  response states that it contains HTML content but does not specify a character set, then the browser may analyze the HTML and attempt to determine which character set it appears to be using. Even if the majority of the HTML actually employs a standard character set such as UTF-8, the presence of non-standard characters anywhere in the response may cause the browser to interpret the content using a different character set. This can have unexpected results, and can lead to cross-site scripting vulnerabilities in which non-standard encodings like UTF-7 can be used to bypass the application's defensive filters.</p>
<p>In most cases, the absence of a charset directive does not constitute a security flaw, particularly if the response contains static content. You should review the contents of affected responses, and the context in which they appear, to determine whether any vulnerability exists. </p>"#,
        remediation: Some(r#"<p>For every response containing HTML content, the application should include within the Content-type header a directive specifying a standard recognized character set, for example <b>charset=ISO-8859-1</b>.
</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CWE-436: Interpretation Conflict"#, url: r#"https://cwe.mitre.org/data/definitions/436.html"# },
        ],
    },
    IssueDefinition {
        type_index: 8389376,
        declared_type_index: 8389376,
        name: r#"HTML uses unrecognized charset"#,
        typical_severity: Severity::Info,
        description: r#"<p>Applications may specify a non-standard character set as a result of typographical errors within the code base, or because of intentional usage of an unusual character set that is not universally recognized by browsers. If the browser does not recognize the character set specified by the application, then the browser may analyze the HTML and attempt to determine which character set it appears to be using. Even if the majority of the HTML actually employs a standard character set such as UTF-8, the presence of non-standard characters anywhere in the response may cause the browser to interpret the content using a different character set. This can have unexpected results, and can lead to cross-site scripting vulnerabilities in which non-standard encodings like UTF-7 can be used to bypass the application's defensive filters.</p>
<p>In most cases, the absence of a valid charset directive does not constitute a security flaw, particularly if the response contains static content. You should review the contents of affected responses, and the context in which they appear, to determine whether any vulnerability exists. </p>"#,
        remediation: Some(r#"<p>For every response containing HTML content, the application should include within the Content-type header a directive specifying a standard recognized character set, for example <b>charset=ISO-8859-1</b>.
</p>"#),
        references: &[],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CWE-436: Interpretation Conflict"#, url: r#"https://cwe.mitre.org/data/definitions/436.html"# },
        ],
    },
    IssueDefinition {
        type_index: 8389632,
        declared_type_index: 8389632,
        name: r#"Content type incorrectly stated"#,
        typical_severity: Severity::Low,
        description: r#"<p>If a  response specifies an incorrect content type then browsers may process the response in unexpected ways. If the  content type is specified to be a renderable text-based format, then the browser will usually attempt to interpret the response as being in that format, regardless of the actual contents of the response. Additionally, some other specified content types might sometimes be interpreted as HTML due to quirks in particular browsers. This behavior might lead to otherwise &quot;safe&quot; content such as images  being rendered as HTML, enabling cross-site scripting attacks in certain conditions.</p>
<p>The presence of an incorrect content type statement typically only constitutes a security flaw when the affected resource is dynamically generated, uploaded by a user, or otherwise contains user input. You should review the contents of affected responses, and the context in which they appear, to determine whether any vulnerability exists.</p>"#,
        remediation: Some(r#"<p>For every response containing a message body, the application should include a single Content-type header that correctly and unambiguously states the MIME type of the content in the response body.</p>
<p>Additionally, the response header &quot;X-content-type-options: nosniff&quot; should be returned in all responses to reduce the likelihood that browsers will interpret content in a way that disregards the Content-type header.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CWE-436: Interpretation Conflict"#, url: r#"https://cwe.mitre.org/data/definitions/436.html"# },
            Classification { title: r#"CAPEC-63: Cross-Site Scripting (XSS)"#, url: r#"https://capec.mitre.org/data/definitions/63.html"# },
        ],
    },
    IssueDefinition {
        type_index: 8389888,
        declared_type_index: 8389888,
        name: r#"Content type is not specified"#,
        typical_severity: Severity::Info,
        description: r#"<p>If a  response does not specify a content type, then the browser will usually analyze the response and attempt to determine the MIME type of its content. This can have unexpected results, and if the content contains any user-controllable data may lead to cross-site scripting or other client-side vulnerabilities.</p>
<p>In most cases, the absence of a content type statement does not constitute a security flaw, particularly if the response contains static content. You should review the contents of affected responses, and the context in which they appear, to determine whether any vulnerability exists. </p>"#,
        remediation: Some(r#"<p>For every response containing a message body, the application should include a single Content-type header that correctly and unambiguously states the MIME type of the content in the response body.</p>"#),
        references: &[
            Reference { title: r#"Web Security Academy: Cross-site scripting"#, url: r#"https://portswigger.net/web-security/cross-site-scripting"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CAPEC-63: Cross-Site Scripting (XSS)"#, url: r#"https://capec.mitre.org/data/definitions/63.html"# },
        ],
    },
    IssueDefinition {
        type_index: 16777472,
        declared_type_index: 16777472,
        name: r#"TLS certificate"#,
        typical_severity: Severity::Medium,
        description: r#"<p>TLS (or SSL) helps to protect the confidentiality and integrity of information in transit between the browser and server, and to provide authentication of the server's identity. To serve this purpose, the server must present an TLS certificate that is valid for the server's hostname, is issued by a trusted authority and is valid for the current date. If any one of these requirements is not met, TLS connections to the server will not provide the full protection for which TLS is designed.</p>
<p>It should be noted that various attacks exist against TLS in general, and in the context of HTTPS web connections in particular. It may be possible for a determined and suitably-positioned attacker to compromise TLS connections without user detection even when a valid TLS certificate is used. </p>"#,
        remediation: None,
        references: &[
            Reference { title: r#"SSL/TLS Configuration Guide"#, url: r#"https://wiki.mozilla.org/Security/Server_Side_TLS"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-295: Improper Certificate Validation"#, url: r#"https://cwe.mitre.org/data/definitions/295.html"# },
            Classification { title: r#"CWE-326: Inadequate Encryption Strength"#, url: r#"https://cwe.mitre.org/data/definitions/326.html"# },
            Classification { title: r#"CWE-327: Use of a Broken or Risky Cryptographic Algorithm"#, url: r#"https://cwe.mitre.org/data/definitions/327.html"# },
        ],
    },
    IssueDefinition {
        type_index: 16777728,
        declared_type_index: 16777728,
        name: r#"Unencrypted communications"#,
        typical_severity: Severity::Low,
        description: r#"<p>The application allows users to connect to it over unencrypted connections. An attacker suitably positioned to view a legitimate user's network traffic could record and monitor their interactions with the application and obtain any information the user supplies. Furthermore, an attacker able to modify traffic could use the application as a platform for attacks against its users and third-party websites. Unencrypted connections have been exploited by ISPs and governments to track users, and to inject adverts and malicious JavaScript. Due to these concerns, web browser vendors are planning to visually flag unencrypted connections as hazardous.</p><p>To exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.</p><p>Please note that using a mixture of encrypted and unencrypted communications is an ineffective defense against active attackers, because they can easily remove references to encrypted resources when these references are transmitted over an unencrypted connection.</p>"#,
        remediation: Some(r#"<p>Applications should use transport-level encryption (SSL/TLS) to protect all communications passing between the client and the server. The Strict-Transport-Security HTTP header should be used to ensure that clients refuse to access the server over an insecure connection.</p>"#),
        references: &[
            Reference { title: r#"Marking HTTP as non-secure"#, url: r#"https://www.chromium.org/Home/chromium-security/marking-http-as-non-secure"# },
            Reference { title: r#"Configuring Server-Side SSL/TLS"#, url: r#"https://wiki.mozilla.org/Security/Server_Side_TLS"# },
            Reference { title: r#"HTTP Strict Transport Security"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-326: Inadequate Encryption Strength"#, url: r#"https://cwe.mitre.org/data/definitions/326.html"# },
            Classification { title: r#"CAPEC-94: Man in the Middle Attack"#, url: r#"https://capec.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CAPEC-157: Sniffing Attacks"#, url: r#"https://capec.mitre.org/data/definitions/157.html"# },
        ],
    },
    IssueDefinition {
        type_index: 16777984,
        declared_type_index: 16777984,
        name: r#"Strict transport security not enforced"#,
        typical_severity: Severity::Low,
        description: r#"<p> The application fails to prevent users from connecting  to it over unencrypted connections.  An attacker able to modify a legitimate user's network traffic could bypass the application's use of SSL/TLS encryption, and use the application as a platform for attacks against its users. This attack is performed by rewriting HTTPS links as HTTP, so that if a targeted user follows a link to the site from an HTTP page, their browser never attempts to use an encrypted connection. The sslstrip tool  automates this process. </p>
<p>
To exploit this vulnerability, an attacker must be suitably positioned to intercept and modify the victim's network traffic.This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure. </p>"#,
        remediation: Some(r#"<p>The application should instruct web browsers to only access the application using HTTPS. To do this, enable HTTP Strict Transport Security (HSTS) by adding a response header with the name 'Strict-Transport-Security' and the value 'max-age=expireTime', where expireTime is the time in seconds that browsers should remember that the site should only be accessed using HTTPS. Consider adding the 'includeSubDomains' flag if appropriate.</p>
<p>Note that because HSTS is a &quot;trust on first use&quot; (TOFU) protocol, a user who has never accessed the application will never have seen the HSTS header, and will therefore still be vulnerable to SSL stripping attacks. To mitigate this risk, you can optionally add the 'preload' flag to the HSTS header, and submit the domain for review by browser vendors.</p>"#),
        references: &[
            Reference { title: r#"HTTP Strict Transport Security"#, url: r#"https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security"# },
            Reference { title: r#"sslstrip"#, url: r#"https://github.com/moxie0/sslstrip"# },
            Reference { title: r#"HSTS Preload Form"#, url: r#"https://hstspreload.appspot.com/"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-523: Unprotected Transport of Credentials"#, url: r#"https://cwe.mitre.org/data/definitions/523.html"# },
            Classification { title: r#"CAPEC-94: Man in the Middle Attack"#, url: r#"https://capec.mitre.org/data/definitions/94.html"# },
            Classification { title: r#"CAPEC-157: Sniffing Attacks"#, url: r#"https://capec.mitre.org/data/definitions/157.html"# },
        ],
    },
    IssueDefinition {
        type_index: 16778240,
        declared_type_index: 16778240,
        name: r#"Mixed content"#,
        typical_severity: Severity::Info,
        description: r#"<p>The application loads pages over HTTPS that load other resources over unencrypted connections. An attacker suitably positioned to view a legitimate user's network traffic could record and monitor their interactions with these resources, which may indirectly disclose information about the user's activity on the application itself. Furthermore, an attacker able to modify traffic could alter these resources and potentially influence the application's appearance and behavior. Due to these concerns, users' web browsers may automatically display warnings and disable affected components of the page. As a result, this vulnerability currently has more of an impact on usability than security.</p><p>To exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.</p>"#,
        remediation: Some(r#"<p>Ensure that all external resources the page references are loaded using HTTPS.</p>"#),
        references: &[
            Reference { title: r#"Mixed Content"#, url: r#"https://developer.mozilla.org/en/docs/Security/MixedContent"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-16: Configuration"#, url: r#"https://cwe.mitre.org/data/definitions/16.html"# },
            Classification { title: r#"CWE-319: Cleartext Transmission of Sensitive Information"#, url: r#"https://cwe.mitre.org/data/definitions/319.html"# },
            Classification { title: r#"CAPEC-117: Interception"#, url: r#"https://capec.mitre.org/data/definitions/117.html"# },
        ],
    },
    IssueDefinition {
        type_index: 16778496,
        declared_type_index: 16778496,
        name: r#"Hidden HTTP 2"#,
        typical_severity: Severity::Info,
        description: r#"<p>
    Clients that support HTTP/2 typically default to HTTP/1.1, and only use HTTP/2 if the server advertises support for it via the ALPN field during the TLS handshake.
</p>
<p>
    Some misconfigured servers that do support HTTP/2 fail to advertise this, making it appear as though they only support HTTP/1.1. This can lead to people overlooking viable HTTP/2 attack surface and missing associated vulnerabilities, such as HTTP/2 downgrade-based request smuggling.
</p>"#,
        remediation: Some(r#"<p>
    If you want to use HTTP/2, make sure the server is configured to advertise it correctly. Otherwise, consider fully disabling it server-side to reduce unnecessary attack surface.
</p>"#),
        references: &[
            Reference { title: r#"HTTP/2: The Sequel is Always Worse"#, url: r#"https://portswigger.net/research/http2"# },
        ],
        classifications: &[
            Classification { title: r#"CWE-912: Hidden Functionality"#, url: r#"https://cwe.mitre.org/data/definitions/912.html"# },
        ],
    },
    IssueDefinition {
        type_index: 134217728,
        declared_type_index: 134217728,
        name: r#"Extension generated issue"#,
        typical_severity: Severity::Info,
        description: r#"<p>This type of issue is used for custom issues that are generated by Burp Suite extensions.</p>"#,
        remediation: None,
        references: &[],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 134250496,
        declared_type_index: 134250496,
        name: r#"Manually generated issue"#,
        typical_severity: Severity::Info,
        description: r#"<p>This type of issue is used for issues that are generated manually within Burp Suite.</p>"#,
        remediation: None,
        references: &[],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 150994944,
        declared_type_index: 150994944,
        name: r#"BCheck generated issue"#,
        typical_severity: Severity::Info,
        description: r#"<p>This type of issue is used for custom issues that are generated by BChecks.</p>"#,
        remediation: None,
        references: &[],
        classifications: &[],
    },
    IssueDefinition {
        type_index: 151027712,
        declared_type_index: 150994944,
        name: r#"Bambda generated issue"#,
        typical_severity: Severity::Info,
        description: r#"<p>This type of issue is used for custom issues that are generated by Bambdas.</p>"#,
        remediation: None,
        references: &[],
        classifications: &[],
    },
];
