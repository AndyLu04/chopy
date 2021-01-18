# IPS 2020 Q4 report
### CVE-2020-8794 (OpenSMTPD RCE)
* Description ([source](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8794))
* An <font color=#FF0000>remote code execution</font> vulnerability exist in OpenSMTPD which affects both client side and server side.
    
* Impact
    * This vulnerability has already existed since 2015.
    * Affected Versions: OpenSMTPD < 6.6.4p1      
    * After the 2018/May OpenSMTPD release version, this vulnerability allows attacker to get <font color=#FF0000>root priviledge</font> to execute any shell command while before this version, attacker can still get non-root priviledge for running shell commands. 
    * Affact region ([source](https://cert.360.cn/warning/detail?id=5ed8d8cc121c223ac27d877f9e7b20b9))
    ![](/uploads/upload_54243574fc7377ef7d302f5a43e2c54e.png)


* Detail
    * The SMTP servers will respond a single-line or multiple-line msg to the client side's command(e.g. EHLO, MAIL FROM).
        * the first line starts with a three-digit code and a hyphen ('-'), followed by an optional text (for example, "250-ENHANCEDSTATUSCODES").

        * the last line begins with the same three-digit code, followed by an optional space (' ') and text (for example, "250 HELP").
    * Vulnerability location:
        * in client side's source code, the mta_io function parses the multiline replies
            ```c=1195
            mta_io(struct io *io, int evt, void *arg)
            {
            ```
            here, the replies are stored in the <font color=#FF0000>"line"</font> variable
            ```c=1133
                    case IO_DATAIN:
                        nextline:
                        line = io_getline(s->io, &len);
            ```
            * use variable <font color=#FF0000>p</font> to get the reply msg of last line
            ```c=1195
                        if (s->replybuf[0] != '\0') {
                            p = line + 4;
            ```         
            then it concatenate the reply msg after the three-digit code to the <font color=#FF0000>reply buffer</font>
            ```c=1201
                            if (strlcat(s->replybuf, p, sizeof s->replybuf) >= sizeof s->replybuf)
            ```
    * Exploits
        1. If the attacker controls a malicious SMTP server and send a reply msg with the "xyz\nstring\0" form of last line, at line 1201  the "string" which can be a shell command waiting to be executed is concatenated into replybuf.
        2. Next, if the three-digit code of reply indicates a temporary error (4yz) or a permanent error (5yz),then the replybuf are written to the "errorline" field of the envelope of the mail that OpenSMTPD is trying to deliver.
        3. Here the attacker can inject new lines into the envelope and change OpenSMTPD's behavior.
        4. The Attacker waits until OpenSMTPD connects to the malicious mail server and respond with a multiline reply (a permanent error) that creates a bounce and injects command into its envelope:
            ```
            ----------------------------------------
            type: mda
            mda-exec: The arbitrary shell command
            dispatcher: local_mail
            mda-user: root
            ----------------------------------------
            ```
            Then the shell command inside <font color=#FF0000>"mda-exec"</font> feild will be executed when OpenSMTPD tries to deliver this bounce, because our injected lines changed its type from MTA (Message Transfer Agent) to MDA (Message Delivery Agent).
    
* Suggestion
    * Virtual patch : Pico IPS rule 8210251 in Signature v5.1.95 (release at 2020/11/20)
    * Official patch :
        * OpenSMTPD 6.6.4p1
* Reference
    * [Qualys Security Advisory (CVE-2020-8794)](https://www.qualys.com/2020/02/24/cve-2020-8794/lpe-rce-opensmtpd-default-install.txt)

### CVE-2018-13379 (Citrix ADC Directory Traversal)
* Description ([source](https://nvd.nist.gov/vuln/detail/CVE-2018-13379))
    * According to the online statistical information about CVE amount of leading SSL VPN vendors, the Fortinet product seems to be an quite secure choice.
        ![](/uploads/upload_417349c1e4bc324671e6831bcf104258.png)

    *  However, there still exsists an <font color=#FF0000> Arbitrary File Read </font> vulnerability in Fortinet SSL VPN product.
    *  The web portal allows unauthenticated attacker to access system files via special crafted HTTP resource requests.
    
* Impact
    * Via exploiting this vulnerability to read system files, the attackers can further more cause heap overflow and gain highest administrator priviledge to do any malicious accativity they want.
    * The affect version of products are:
        *  FortiOS 6.0.0 to 6.0.4 
        *  FortiOS 5.6.3 to 5.6.7
        *  FortiOS 5.4.6 to 5.4.12
        *  <font color=#FF0000> ONLY if the SSL VPN service (web-mode or tunnel-mode) is enabled.</font>

* Detail
    * The system uses the following "snprintf" functiom to fetch the corresponding language file
      
      ```c=
      snprintf(s, 0x40, "/migadmin/lang/%s.json", lang);
      ```
      
      It builds the json file path with the parameter <font color=#FF0000>lang</font>.
      
    * As we can see, there's no protection, but a file extension appended automatically. Ostensibly, it seems that we can only read json file through this function. However, we could actually misapply the feature of snprintf. 
    * According to the description of function sprintf, it writes at most <font color=#FF0000>size-1 bytes</font> into the output string. In other words, if attacker make it exceed the buffer size, the .json will be stripped. Then attacker can read anything without the restriction on ".json" format.
    
* Suggestion
    * Virtual patch : Pico IPS rule 8210213 in Signature v5.1.97 (release at 2020/12/04)
    * Official patch :
        * For FortiOS 6.0.0 to 6.0.4 version, upgrade to 6.2.0
        * For FortiOS 5.6.3 to 5.6.7 version, upgrade to 5.6.9
        * For FortiOS 5.4.6 to 5.4.12 version, upgrade to 6.0.5
        * Or 6.2.0 and above。
* Reference
    * [Breaking the Fortigate SSL VPN](https://devco.re/blog/2019/08/09/attacking-ssl-vpn-part-2-breaking-the-Fortigate-ssl-vpn/)
    
### CVE-2019-19781 (Citrix ADC Directory Traversal)
* Description ([source](https://nvd.nist.gov/vuln/detail/CVE-2019-19781))
* An <font color=#FF0000>directory traversal</font> vulnerability with 9.8 critical CVSS v3.1 base score was discovered in Citrix Application Delivery Controller (ADC), Citrix Gateway and NetScaler Gateway. 
    
* Impact
    * Attackers can use this vulnerability to get unauthorithed priviledge to access sensitive files.
    * The affect version of products are:
        *  Citrix ADC and Citrix Gateway version 13.0 all supported builds
        *  Citrix ADC and NetScaler Gateway version 12.1 all supported builds
        *  Citrix ADC and NetScaler Gateway version 12.0 all supported builds
        *  Citrix ADC and NetScaler Gateway version 11.1 all supported builds
        *  Citrix NetScaler ADC and NetScaler Gateway version 10.5 all supported builds
    * Affect region:
    * More than <font color=#FF0000>80000</font> of devices are affected by this vulnerability around the world.
    ![](/uploads/upload_65486ce2b8acc44c4670df119751d001.png)

* Detail
    * The root cause of this vulnerability is handling the pathname improperly. 
        1. Since the system doesn’t have a data sanitation check, when system receives a request with path like /vpn/../vpns/services.html, the Apache server running in the products transforms the path from <font color=#3A9933>/vpn/../vpns/</font> into simply <font color=#FF0000>/vpns/</font>. 
        2. The Apache server will first use the path "/vpn/" to check whether the requester has the priviledge to access the data under this path and if so, the requester will gain the access right.
        3. However the next path expression <font color=#FF0000>".."</font> here will redirect the path to the upper directory of /vpn/ and then set path to /vpns/.
        4. This is how the exploits happend --> using the previledge of accessing path "/vpn/" to access path "/vpns".
    * This can be more severe, if the attacker makes a crafted XML file in the vulnerable server by a POST request and then makes another HTTP request to visit that file, the malicious code inside the XML file may be executed.
    
* Suggestion
    * Virtual patch : Pico IPS rule 8210213 in Signature v5.1.99 (release at 2020/12/18)
    * [Critix official mitigation steps](https://support.citrix.com/article/CTX267679)
* Reference
    [CVE-2019-19781](https://unit42.paloaltonetworks.com/exploits-in-the-wild-for-citrix-adc-and-citrix-gateway-directory-traversal-vulnerability-cve-2019-19781/)
    [Critix path traversal vulnerability point](https://www.anquanke.com/post/id/196898)


