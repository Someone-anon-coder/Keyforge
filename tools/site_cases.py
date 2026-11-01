# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Someone-anon-coder
"""Hand-written site cases for algorithm v2: (group, input, expected v2 site, expected full-host site).

The expectations are written by hand from how each service really works, not generated from the
code, so a wrong rule shows up as a failing case. tools/make_vectors.py copies these into
tests/normalize-fuzz.json (with Python's output) and tests/sites-v2.json (with the expectations).
"""

CASES = [
    # One account across many subdomains
    ("one account, many subdomains", "accounts.google.com", "google.com", "accounts.google.com"),
    ("one account, many subdomains", "https://mail.google.com/mail/u/0/", "google.com", "mail.google.com"),
    ("one account, many subdomains", "https://myaccount.google.com/security?hl=en", "google.com", "myaccount.google.com"),
    ("one account, many subdomains", "google.com", "google.com", "google.com"),
    ("one account, many subdomains", "https://www.amazon.com/ap/signin", "amazon.com", "amazon.com"),
    ("one account, many subdomains", "sellercentral.amazon.com", "amazon.com", "sellercentral.amazon.com"),
    ("one account, many subdomains", "https://github.com/login", "github.com", "github.com"),
    ("one account, many subdomains", "gist.github.com", "github.com", "gist.github.com"),
    ("one account, many subdomains", "docs.github.com", "github.com", "docs.github.com"),
    # One account across different registrable domains: no rule can join these, the user types one name
    ("one account, several domains", "login.live.com", "live.com", "login.live.com"),
    ("one account, several domains", "https://login.microsoftonline.com/common/oauth2", "microsoftonline.com", "login.microsoftonline.com"),
    ("one account, several domains", "account.microsoft.com", "microsoft.com", "account.microsoft.com"),
    ("one account, several domains", "accounts.youtube.com", "youtube.com", "accounts.youtube.com"),
    ("one account, several domains", "https://accounts.google.co.in/", "google.co.in", "accounts.google.co.in"),
    ("one account, several domains", "google.co.in", "google.co.in", "google.co.in"),
    # Same brand, separate accounts per country
    ("separate accounts per country", "https://www.amazon.in/", "amazon.in", "amazon.in"),
    ("separate accounts per country", "amazon.com", "amazon.com", "amazon.com"),
    ("separate accounts per country", "www.amazon.co.uk", "amazon.co.uk", "amazon.co.uk"),
    ("separate accounts per country", "amazon.com.au", "amazon.com.au", "amazon.com.au"),
    ("separate accounts per country", "accounts.zoho.in", "zoho.in", "accounts.zoho.in"),
    ("separate accounts per country", "https://accounts.zoho.com/signin", "zoho.com", "accounts.zoho.com"),
    ("separate accounts per country", "accounts.zoho.eu", "zoho.eu", "accounts.zoho.eu"),
    # Tenants the Public Suffix List already separates
    ("tenants in the PSL", "acme.myshopify.com", "acme.myshopify.com", "acme.myshopify.com"),
    ("tenants in the PSL", "https://admin.acme.myshopify.com/", "acme.myshopify.com", "admin.acme.myshopify.com"),
    ("tenants in the PSL", "evil.myshopify.com", "evil.myshopify.com", "evil.myshopify.com"),
    ("tenants in the PSL", "someone.github.io", "someone.github.io", "someone.github.io"),
    ("tenants in the PSL", "https://someone.github.io/project/", "someone.github.io", "someone.github.io"),
    ("tenants in the PSL", "github.io", "github.io", "github.io"),
    ("tenants in the PSL", "myblog.blogspot.com", "myblog.blogspot.com", "myblog.blogspot.com"),
    ("tenants in the PSL", "blogspot.com", "blogspot.com", "blogspot.com"),
    ("tenants in the PSL", "myapp.herokuapp.com", "myapp.herokuapp.com", "myapp.herokuapp.com"),
    ("tenants in the PSL", "d111111abcdef8.cloudfront.net", "d111111abcdef8.cloudfront.net", "d111111abcdef8.cloudfront.net"),
    ("tenants in the PSL", "mybucket.s3.amazonaws.com", "mybucket.s3.amazonaws.com", "mybucket.s3.amazonaws.com"),
    # Tenants the PSL does NOT list: v2 collapses them; "use full hostname" is the way out
    ("tenants missing from the PSL", "acme.atlassian.net", "atlassian.net", "acme.atlassian.net"),
    ("tenants missing from the PSL", "https://acme.slack.com/", "slack.com", "acme.slack.com"),
    ("tenants missing from the PSL", "acme.zendesk.com", "zendesk.com", "acme.zendesk.com"),
    ("tenants missing from the PSL", "https://acme.my.salesforce.com/", "salesforce.com", "acme.my.salesforce.com"),
    # Multi-part suffixes and deep hosts
    ("multi-part suffixes", "www.example.co.in", "example.co.in", "example.co.in"),
    ("multi-part suffixes", "mail.example.co.in", "example.co.in", "mail.example.co.in"),
    ("multi-part suffixes", "https://login.portal.example.gov.in/x", "example.gov.in", "login.portal.example.gov.in"),
    ("multi-part suffixes", "lms.college.ac.in", "college.ac.in", "lms.college.ac.in"),
    ("multi-part suffixes", "a.b.c.example.co.uk", "example.co.uk", "a.b.c.example.co.uk"),
    ("multi-part suffixes", "www.bbc.co.uk", "bbc.co.uk", "bbc.co.uk"),
    ("multi-part suffixes", "co.uk", "co.uk", "co.uk"),
    ("multi-part suffixes", "co.in", "co.in", "co.in"),
    ("multi-part suffixes", "shop.example.com.cn", "example.com.cn", "shop.example.com.cn"),
    ("multi-part suffixes", "foo.example.zzz", "example.zzz", "foo.example.zzz"),
    ("multi-part suffixes", "a.b.ck", "a.b.ck", "a.b.ck"),
    ("multi-part suffixes", "x.a.b.ck", "a.b.ck", "x.a.b.ck"),
    ("multi-part suffixes", "www.ck", "ck", "ck"),  # v1 drops "www." first, so the exception rule never sees it
    ("multi-part suffixes", "mail.www.ck", "www.ck", "mail.www.ck"),
    ("multi-part suffixes", "city.kawasaki.jp", "city.kawasaki.jp", "city.kawasaki.jp"),
    ("multi-part suffixes", "x.city.kawasaki.jp", "city.kawasaki.jp", "x.city.kawasaki.jp"),
    ("multi-part suffixes", "x.y.kawasaki.jp", "x.y.kawasaki.jp", "x.y.kawasaki.jp"),
    ("multi-part suffixes", "z.x.y.kawasaki.jp", "x.y.kawasaki.jp", "z.x.y.kawasaki.jp"),
    # Hosts with no registrable domain
    ("no registrable domain", "localhost", "localhost", "localhost"),
    ("no registrable domain", "http://localhost:3000/app", "localhost", "localhost"),
    ("no registrable domain", "intranet", "intranet", "intranet"),
    ("no registrable domain", "192.168.1.1", "192.168.1.1", "192.168.1.1"),
    ("no registrable domain", "https://192.168.1.1:8443/admin", "192.168.1.1", "192.168.1.1"),
    ("no registrable domain", "http://[::1]:8080/", "[::1]", "[::1]"),
    ("no registrable domain", "a..b.com", "a..b.com", "a..b.com"),
    ("no registrable domain", "www.github.io", "github.io", "github.io"),
    # International names
    ("international names", "bücher.de", "bücher.de", "bücher.de"),
    ("international names", "https://shop.bücher.de/x", "bücher.de", "shop.bücher.de"),
    ("international names", "shop.xn--bcher-kva.de", "bücher.de", "shop.bücher.de"),
    ("international names", "ｍａｉｌ.ｇｏｏｇｌｅ.ｃｏｍ", "google.com", "mail.google.com"),
    ("international names", "www.食狮.公司.cn", "食狮.公司.cn", "食狮.公司.cn"),
    ("international names", "xn--80ak6aa92e.com", "аррӏе.com", "аррӏе.com"),
    # Phishing pairs: every one must differ from the real site
    ("phishing", "https://paypal.com/signin", "paypal.com", "paypal.com"),
    ("phishing", "https://www.paypal.com/", "paypal.com", "paypal.com"),
    ("phishing", "https://paypa1-secure-login.com/", "paypa1-secure-login.com", "paypa1-secure-login.com"),
    ("phishing", "https://paypal.com.evil.com/login", "evil.com", "paypal.com.evil.com"),
    ("phishing", "https://paypal.com@evil.com/", "evil.com", "evil.com"),
    ("phishing", "https://evil.com/paypal.com", "evil.com", "evil.com"),
    ("phishing", "https://evil.com\\@paypal.com", "evil.com", "evil.com"),
    ("phishing", "https://paypal.com.evil.co.uk/", "evil.co.uk", "paypal.com.evil.co.uk"),
    ("phishing", "https://paypal.evil.github.io/", "evil.github.io", "paypal.evil.github.io"),
    ("phishing", "https://paypal.com:443@evil.com:8080/", "evil.com", "evil.com"),
]
