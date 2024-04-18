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
|{{< imagelink src=/img/miner_delivery/error-log.png link=/img/miner_delivery/error-log.png position=center >}}|

While at first glance this *appears* to make no sense, we can break down the request, see what it does, and enumerate the delivery mechanism of this specific malware.

&nbsp;

## Breaking it Down

The first few segments of the log entry are just the request timestamp, entry type, process, etc. Basically nothing of relevance for what we're interested in. Next we can see that the log entry appears to have two *almost* identical requests. The first copy is the access error, and the second is the reason for access error (filesystem path).

|After trimming the fat and duplicate of the request we are left with the following:|
|:---:|
|{{< imagelink position=center src=/img/miner_delivery/request.png link=/img/miner_delivery/request.png position=center >}}|

&nbsp;

### Compromising the Machine

- #### Vulnerability and Initial Access

The first segment to look at is this part:
|Initial Exploit|
|:---:|
|{{< imagelink src=/img/miner_delivery/vulnerability.png link=/img/miner_delivery/vulnerability.png position=center >}}|


Doing a quick Google search with that part returns information about [CVE-2022-26134](https://nvd.nist.gov/vuln/detail/CVE-2022-26134) which [NIST](https://nvd.nist.gov/vuln) describes it as:

>In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would **allow an unauthenticated attacker to execute arbitrary code** on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

**"allow an unauthenticated attacker to execute arbitrary code"** - This means with this the request could run commands on the target system *if vulnerable*. The device I was working with doesn't use Atlassian Confluence, so it hit a dead-end here. But given a server that *is* vulnerable, and a carefully tailored request, anyone could make the system run system commands.


Explanation of the specific vulnerability being exploited is beyond the scope of this writing, but there are articles and examples such as [here](https://medium.com/@sivaramaaa/nashorn-script-engine-injection-eafc88a7623a) and [here](https://darktrace.com/blog/detection-and-guidance-for-the-confluence-cve-2022-26134-zero-day), and even a [room at TryHackMe](https://tryhackme.com/r/room/cve202226134) that go more in depth for those interested.

&nbsp;

- #### Exploiting and Execution

Next let's take a look and see exatly what commands it was trying to execute by analyzing the payload for `command()`:
|Exploit Payload|
|:---:|
|{{< imagelink src=/img/miner_delivery/request-payload-encoded.png link=/img/miner_delivery/request-payload-encoded.png position=center >}}|


Wow, what is going on here?

What this contains is a list for the `java.lang.ProcessBuilder().command()` to process.
- `bash` and `-c` tells it to interpret the following with the `bash` shell.
- `echo` a base64 encoded string and pipe to `base64 -d` to decode
- pipe output of `base64 -d` to another `bash` to execute.

&nbsp;

We will need to decode this string and see what it says in order to understand more. At this point all we can see is that it `echo` a seemingly random string of characters to be read by `base64` and executed after decoding.
Using either `base64 -d` command or [CyberChef](https://gchq.github.io/CyberChef/) and decoding the string we get:
|Decoded Exploit Payload|
|:---:|
|{{< imagelink src=/img/miner_delivery/request-payload-decoded.png link=/img/miner_delivery/request-payload-decoded.png position=center caption="payload decoded with `base64 -d`" >}}|


**Now this is starting to look interesting.**

We have found what appears to be a script inteneded for execution on a victim system. Not all devices have the `curl` program, so relying on that binary to be on the system would potentially hinder the ability for this payload to function. Instead, what this script does is create its own function to use `/dev/tcp` for file transfer.

- #### Staging

Once the initial payload is executed it downloads this new script `w.sh`:
|Stager Script `w.sh`|
|:---:|
|{{< imagelink src=/img/miner_delivery/stager-init.png link=/img/miner_delivery/stager-init.png position=center >}}|


Boiled down, this new script starts by assigning some variables for reference later in the script such as the path to `ls` and the domain and URL path for future downloads.
It then does the following:
- find the `chattr` binary and move it to `zzhcht` (installing e2fsprogs package if not found and possible)
- set an environment variable for the new location of the renamed `chattr` binary
- copies the `ls` binary to replace `chattr`
- sets attributes on the replaced `chattr` (originally `ls`) to ensure the changes aren't modified. As defined in the `chattr` manpage:
    > a - A file with the 'a' attribute set can only be opened in append mode for writing.  Only the superuser or a process possessing the CAP_LINUX_IMMUTABLE capability can set or clear this attribute.
    >
    > i - A file with the 'i' attribute cannot be modified: it cannot be deleted or renamed, no link can be created to this file, most of the file's metadata can not be modified, and the file can not be opened in write mode. Only the superuser or a process possessing the CAP_LINUX_IMMUTABLE capability can set or clear this attribute.

- check if the current user ID is root and retrieve another script depending on result:
    - if user is root download `ar.sh`
    - if user *is not* root download `ai.sh`

### Setting up Shop

At this point in the exploit we're at a fork in the road. If the script has access as system administrator or `root` it has free reign of the system. But what if it only has normal user or unprivileged access? We will start by looking at it from a low-privileged user basis first and analyze the script.

- #### Unprivileged System Access

|Unprivileged Script `ai.sh`|
|:---:|
|{{< imagelink src=/img/miner_delivery/stager-unpriv.png link=/img/miner_delivery/stager-unpriv.png position=center caption="`proxyip` blurred because it may be another compromised device" >}}|

This script starts with setting some variables like `proxyip` and `media_url` as can be seen in the [screenshot](/img/miner_delivery/stager-unpriv.png) above. It then sets up a `check_exists` function that checks that the system is not already communicating with the `proxyip` which would signal that that the miner is probably already running on this system.

After results from the `check_exists` function, the script continues to download the `media_url` and output to a file named `xm.jpg`. But if this file is a JPEG, why is it following up the download by running `tar`, `chmod`, and `./start`?

To get to the bottom of this we'll download and examine the file with `file` and see what it does contain.

|Reported File Type of `xm.jpg`|
|:---:|
|{{< imagelink src=/img/miner_delivery/xm-jpg-file.png link=/img/miner_delivery/xm-jpg-file.png position=center >}}|

Well, the `file` output explains the script running `tar` on the file after the download. It is a compressed TAR archive, not an actual JPEG.
For the next step we will list the contents of this tarball and see what it contains.

|List of Contents `xm.jpg`|
|:---:|
|{{< imagelink src=/img/miner_delivery/xm-jpg-list.png link=/img/miner_delivery/xm-jpg-list.png position=center >}}|

|`xm.jpg` contents file information|
|:---:|
|{{< imagelink src=/img/miner_delivery/stager-unpriv-xm-files.png link=/img/miner_delivery/stager-unpriv-xm-files.png position=center >}}|

**BINGO!** we've reached the plant.

The 'unprivileged' branch of the script downloads the plant as a compressed TAR archive masking itself as a JPEG image, then unpacks the archive and makes the `start` binary found in the archive executable to continue by running `./start`.

There are interesting files in the archive to examine, of course, but that will be discussed later after we examine the 'privileged' branch of the stager script.

- #### Privileged System Access

This script is **much** longer than the unprivileged script (486 lines compared to 29) and has *a lot* going on, so we will dissect and analyze.

The first section to look at is the function calls at the bottom of the script. From there we will examine what the functions being called perform.

In the initialization there are variable assignments for `domain`, `mainurl`, `miner_url`, and `rshell_url` to be visited later in the functions. The function calls at the bottom of the script outlines the order the functions will be called in. We will follow this map to determine what the script is doing.

|Initialization|Function Calls|
|:---:|:---:|
|{{< imagelink src=/img/miner_delivery/stager-priv-init.png link=/img/miner_delivery/stager-priv-init.png position=center >}}|{{< imagelink src=/img/miner_delivery/stager-priv-funccalls.png link=/img/miner_delivery/stager-priv-funccalls.png position=center >}}

Starting in the function call section of the script there is the `m_command()` function that checks the work from the initial stager script `w.sh` regarding `chattr`.
|m_command() function|
|:---:|
|{{< imagelink src=/img/miner_delivery/stager-priv-m_command.png link=/img/miner_delivery/stager-priv-m_command.png position=center >}}|

The next functions called are `env_set()` and `clean_logs()`.
|env_set() function|clean_logs() function|
|:---:|:---:|
|{{< imagelink src=/img/miner_delivery/stager-priv-env_set.png link=/img/miner_delivery/stager-priv-env_set.png position=center >}}|{{< imagelink src=/img/miner_delivery/stager-priv-clean_logs.png link=/img/miner_delivery/stager-priv-clean_logs.png position=center >}}|

The `env_set()` function performs the following:
- disable firewall `firewalld`
- set maximum `ulimit` for resources (YOLO SEND IT!! mode)
- sets some environment variables to take care of `history` and `PATH`
- disable SELINUX and the kernel watchdog (is the system taking to long to respond?)
- set DNS resolver hosts to Google (8.8.8.8) and a Chinese DNS resolver 114DNS (114.114.114.114)
- clear and takeover `crontab` just in case a system cron job tries to periodically interfere with the new operations

Then the `clean_logs()` function does just as it says and iterates through the log files truncating each as an empty file.

Continuing through the function calls we find the `download_f()` function:
|download_f() function|
|:---:|
|{{< imagelink src=/img/miner_delivery/stager-priv-download_f.png link=/img/miner_delivery/stager-priv-download_f.png position=center >}}|

This function creates the directory `/var/tmp/.11` if it doesn't already exist (`MOHOME` from the [initialization](/img/miner_delivery/stager-priv-init.png)) and checks to make sure the `sshd` binary doesn't already exist at that location. If the `sshd` binary exists it will delete and download a new copy by retrieving the `enbash.tar` file from the URL stored in `miner_url`, storing it as `debash.tar` and extracting the contents. It then will check for a `bioset` binary in the same location and downloads that if needed by retrieving the `enbio.tar` file, storing it as `debio.tar` and extracting the contents.

|`debash.tar`|`debio.tar`|
|:---:|:---:|
|{{< imagelink src=/img/miner_delivery/debash-tar-list.png link=/img/miner_delivery/debash-tar-list.png position=center >}}|{{< imagelink src=/img/miner_delivery/debio-tar-list.png link=/img/miner_delivery/debio-tar-list.png position=center >}}|

|`debash.tar` & `debio.tar` file information|
|:---:|
|{{< imagelink src=/img/miner_delivery/stager-priv-enbash_enbio-files.png link=/img/miner_delivery/stager-priv-enbash_enbio-files.png position=center >}}|









<!-- 



Starting at the top we can see some variable assignments for `domain`, `mainurl`, `miner_url`, `rshell_url` to be used later in the script. Next, the `ar.sh` script contains a function to check to make sure the `chattr` replacement from the staging script is in place, and the test with `netstat` for current connection to the proxy similar to the unprivileged script. the next function installs build software to compile binaries from source and some additional tools.

Following the checks and tools installs, the next functions do the following:
- disable firewall `firewalld`
- set maximum `ulimit` for resources (YOLO SEND IT!! mode)
- sets some environment variables to take care of `history` and `PATH`
- disable SELINUX and the kernel watchdog (is the system taking to long to respond?)
- set DNS resolver hosts to Google (8.8.8.8) and a Chinese DNS resolver 114DNS (114.114.114.114)
- clear and takeover `crontab` just in case a system cron job tries to periodically interfere with the new operations


|Privileged Script `ar.sh` (section 2 - ssh access)|
|:---:|
|{{< imagelink src=/img/miner_delivery/stager-priv-ssh.png link=/img/miner_delivery/stager-priv-ssh.png position=center >}}|

This function adds SSH keys to `/root/.ssh` for remote SSH access to the `root` account on the system.  The kanji comment on line 108 translates to 'optimization' or 'majorization'.



-->











