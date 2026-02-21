---
title: "Crack The Gate 2"
date: 2026-02-20
lastmod: 2026-02-21
description: "Bypass IP-based rate limiting using X-Forwarded-For header spoofing to brute-force credentials in PicoCTF Crack The Gate 2."
summary: "Bypass IP-based rate limiting via X-Forwarded-For spoofing to brute-force credentials without being blocked."
tags: ["picoctf", "web-exploitation"]
categories: ["write-ups"]
draft: false
---

## Overview

> **Category:** Web Exploitation

> **Difficulty:** Medium

![](images/challenge-info.png)

This challenge gives us a **login page**, a **username** and a **password wordlist**. Normally, we can simply perform password brute-force with **Burp Intruder**. However, the server has **IP-based rate-limit** mechanism, we will be blocked after 1 failed attempt, so we can't brute-force without some tricks (**X-Forwarded-For** header)

## Solving Process

First, I access the website and see the content inside the password list to have an idea what this challenge is about.

The password list has only **20 lines**, so I though I can just try every single of them.

![](images/password-list-content.png)

When I access the challenge website, I see a **login page**, so I use the username from the challenge info (ctf-player@picoctf.org) and pair with each password in the list. The result is I got **blocked** after just 1 failed attempt.

![](images/get-blocked.png)

Now I know the server has some kind of **rate-limit** mechanism. Based on past experience and a quick Google Search, I guess the server use **IP-based** rate-limit mechanism because it's one of the most common type and I don't think this medium challenge will use API key rate-limit.

![](images/search-for-most-common-rate-limit-type.png)

Therefore, I open Burp, redo these steps above and transfer the **/login** request to **Burp Repeater** for some experiments. After that, I do a quick Google search for bypass techniques and the **X-Forwarded-For** header seems to have potential.

![](images/search-for-bypass-technique.png)

After having the bypass technique, I add the **X-Forwarded-For** header with a **random** IP (`10.10.10.100`) inside the login request and the result shows that I **successfully bypass** the rate-limit mechanism.

**_Before_**
![](images/failed-attempt.png)

**_After_**
![](images/bypass-successfully.png)

Almost done. Now I need to perform **password brute-force** without being blocked, so I transfer the login request to **Burp Intruder** tab. There are 2 things need to be iterate: the **password field** and the IP in **X-Forwarded-For** header, so that we can bypass the rate-limit mechanism. Therefore, I change the request to this layout:

![](images/config-intruder-request.png)

I use **Pitchfork Attack** mode because it can put 2 set of payload into 2 different positions. For the second position (the password field), I paste the password list content in the Payload config tab and see 20 lines, so I need 20 IP from position 1 (the X-Forwarded-For header), I choosed this IP range: `10.10.10.101 - 10.10.10.120`

**_Password Field Config_**
![](images/password-field-config.png)

**_X-Forwarded-For Header Config_**
![](images/position-1-config.png)

Finally, I start the attack and I found the **successful response** to get the flag.

![](images/found-the-flag.png)

## Flag

```text
picoCTF{xff_byp4ss_brut3_6cf524b1}
```

## Lessons Learned

The **X-Forwarded-For (XFF)** header is a de facto HTTP standard used to identify the originating IP address of a client connecting to a **web server** through a **proxy** or **load balancer**. Because proxies hide the original client IP, this header is crucial for logging, geolocation, and rate limiting. However, it can be **manipulated easily** by bad actors.

## Mitigations

1. **DON'T trust client's IP from header:** Bad actors can easily manipulate that. Rate-limit mechanism should rely on real IP from TCP connection, or combine with additional authentication like sessions, tokens, keys, CAPTCHA,...

2. If it's **mandatory** to use XFF (because of a load balancer), **ONLY** accept headers from trusted proxies (whitelist the load balancer's IP addresses)
3. Implementing **account lockout** based on username.
4. **Unusual logging and alerts:** the same username being attempted from dozens of different IPs in a short period of time is a clear sign of credential stuffing/brute force.

## References

- **Challenge link:** https://play.picoctf.org/practice/challenge/521
- **Burp Intruder - Pitchfork Attack:** https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/attack-types
