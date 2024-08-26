# AOCL-Cryptography Security Policy
## Reporting Security Issues
If you think you have found a vulnerability in AOCL-Cryptography, then please send an email to the PSIRT team at AMD [psirt@amd.com](mailto:psirt@amd.com). Detailed information about reporting security vulnerabilities is described in [AMD Product Security Page](https://www.amd.com/en/resources/product-security.html#vulnerability).

## Security Incident Handling Process
AMD currently uses Common Vulnerability Scoring System (CVSS) version 3.1 to assess severity and is currently in the process of transitioning from CVSS 3.1 to CVSS 4.0. Throughout this transition period, our security bulletins will include both scores for reference. Use of CVSS 3.1 will be phased out in future bulletins.

The AMD Product Security Incident Response Team (PSIRT) is the focal point for reporting potential AMD product security issues; AMD PSIRT interfaces with the product security ecosystem, including security researchers, industry peers, government organizations, customers, and vendors, working together to report potential AMD product security issues.

The PSIRT team, working with various teams within AMD, follows the following high-level process:
1.	Triage – Review submitted information, logs issue and assigns ticket ID, and identifies appropriate engineering team(s).
2.	Analysis – Validates issues determining severity, impact and criticality.
3.	Remediate – If remediation is required works with business unit and product development to define approach and plans.
4.	Disclosure – Appropriate notification to affected customers and/or issuance of public security bulletin.
5.	Review – Leverage feedback from customers, researchers and internal teams to further improve product security.
 
For more information, please visit [AMD Product Security Page](https://www.amd.com/en/resources/product-security.html#vulnerability).

## Threat Model
By ensuring algorithms in AOCL-Cryptography are constant time, it  aims to be secure against remote timing attacks. It also provides security against known attacks. Implementations of RSA and ECDH are resistant to known side channel attacks. Some threats fall beyond the scope of AOCL-Cryptography’s threat model such as

1.	CPU/Hardware flaws.
2.	Side Channel Attacks in a Same Machine.
3.	Injecting Fault Physically by the Attacker.
4.	Observing side channels such as Power, ADC measurements, etc.

Although AOCL-Cryptography might fix some vulnerabilities which are out of scope of the threat model, no CVEs (Common Vulnerabilities and Exposures) will be assigned for them since they are not caused due to the software itself.

## Issue Severity
1.	Critical – Will be fixed as soon as possible.
2.	High – Will be fixed with higher priority.
3.	Medium – Will be fixed in the next release.
4.	Low – Maybe fixed in the next release.

## Time Duration for Mitigation.
As an upstream provider and participant in Coordinated Vulnerability Disclosure (CVD), AMD requires sufficient time between the initial report and public disclosure.

Some issues may require AMD to provide a mitigation to our customers, who will then integrate, and ship patched products. Other issues may require a coordinated approach where certain aspects of a mitigation may be addressed by AMD and other aspects addressed by various eco-system vendors. In all cases, AMD works to integrate any needed changes and validate mitigations while coordinating any associated disclosures.

Disclosure timeliness is determined on an issue-by-issue basis, appropriate to the situation, and with protection of the end-user in mind. In some cases, disclosure may be completed in the common embargo time period of 90 days. In most cases, however, due to eco-system and product complexity, mitigations can take longer to develop, integrate, and provide to end-users. In these cases, a longer embargo period is needed to allow vendors and partners to adequately patch systems.

For more information, please visit [AMD Product Security Page](https://www.amd.com/en/resources/product-security.html#vulnerability).

