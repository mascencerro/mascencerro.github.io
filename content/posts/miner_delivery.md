---
title: "Miner Delivery"
date: 2024-04-17T11:52:05-05:00
draft: true
toc: true
tags: ["iot", "malware", "crypto", "miner", "malware delivery", "enumeration"]
---

## Discovery
A few weeks ago I was reworking a proof-of-concept exploit for a specific IoT device and while looking through the web service error log on the device, I noticed a few garbled mumbo-jumbo entries like in the following screenshot. These weren't requests I had made to the device, but from another device (more than likely compromised) attempting to exploit a vulnerability and compromise the device I was working on. Seeing as the request is probably being made from a compromised victim device, I masked the specific requestor IP address just in case.

|Error log entry for invalid request|
|:---:|
{{< imagelink src=/img/miner_delivery/error-log.png link=/img/miner_delivery/error-log.png >}}

While at first glance this *appears* to make no sense, we can break down the request, see what it does, and enumerate the delivery mechanism of this specific malware.

---
&nbsp;

## Breaking it Down

The first few segments of the log entry are just the request timestamp, entry type, process, etc. Basically nothing of relevance for what we're interested in. Next we can see that the log entry appears to have two *almost* identical requests. The first copy is the access error, and the second is the reason for access error (filesystem path).

|After trimming the fat and duplicate of the request we are left with the following:|
|:---:|
{{< imagelink position=center src=/img/miner_delivery/request.png link=/img/miner_delivery/request.png >}}


### But, what does this all mean?

- #### Vulnerability and Initial Access

The first segment to look at is this part:
{{< imagelink src=/img/miner_delivery/vulnerability.png link=/img/miner_delivery/vulnerability >}}

Doing a quick Google search with that part returns information about [CVE-2022-26134](https://nvd.nist.gov/vuln/detail/CVE-2022-26134) which describes it as:

>In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

**"allow an unauthenticated attacker to execute arbitrary code"** - This means with this the request could run commands on the target system *if vulnerable*. The device I was working with doesn't use Confluence, so it hit a dead-end here. But given a server that *is* vulnerable, and a carefully tailored request, anyone could make the system run system commands.
&nbsp;


- #### Exploiting and Execution

Next we'll look and see what commands it was trying to run:
{{< imagelink src=/img/miner_delivery/request-payload-encoded.png link=/img/miner_delivery/request-payload-encoded.png >}}

Wow, what is going on here?

What this contains is a list for the `java.lang.ProcessBuilder().command()` to process.
- `bash` and `-c` tells it to interpret the following with the `bash` shell.
- `echo` a base64 encoded string and pipe to `base64 -d` to decode
- pipe output of `base64 -d` to another `bash` to execute.
&nbsp;

We need to decode this string and see what it says.
Using either `base64 -d` command or [CyberChef](https://gchq.github.io/CyberChef/) and decoding the string we get:

{{< imagelink src=/img/miner_delivery/request-payload-decoded.png link=/img/miner_delivery/request-payload-decoded.png >}}


