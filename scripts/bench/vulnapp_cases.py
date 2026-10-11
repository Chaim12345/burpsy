#!/usr/bin/env python3
"""VulnerableApp case catalogue: family -> parameter, and VulnerabilityType -> CWE.

The app's /scanner endpoint gives, per case, a URL, a method, a variant (UNSECURE/SECURE) and a
list of VulnerabilityType names. It does NOT give the request parameter the case is reached
through: every handler binds `@RequestParam Map<String,String>`, so the parameter name lives only
in the page's own JavaScript (`?id=`, `?fileName=`, `?value=` ...). This module pairs the two.

Two tables, each with its provenance:

  FAMILY_PARAMS   from the per-family template JS in the app repo
                  (src/main/resources/static/templates/<Family>/LEVEL_*/[A-Za-z]*.js). One
                  parameter per family is what the app's own UI sends; a level that reads a
                  different name would be a distinct template directory, so the map is
                  per-directory, not per-endpoint.
  TYPE_CWES       from org.sasanlabs.vulnerability.types.VulnerabilityType — the enum's
                  constructor is (cweID, wascID), so this is the app's own ground-truth mapping,
                  not a judgement of ours. A tuple because a few types map to more than one CWE.

This file is data. The harness (run_vulnapp.py) imports it; a change to the app's enum or a
family's parameter is a one-line edit here, and the tables are asserted against the live app by
`--verify-params`.
"""

# Family (the path segment after /VulnerableApp/) -> the query/body parameter its UI sends.
FAMILY_PARAMS = {
    "AuthenticationVulnerability": "username",
    "BlindSQLInjectionVulnerability": "id",
    "CachePoisoning": "level",
    "CommandInjection": "ipaddress",
    "ErrorBasedSQLInjectionVulnerability": "id",
    "Http3xxStatusCodeBasedInjection": "returnTo",
    "IDORVulnerability": "id",
    "JWTVulnerability": "JWT",
    "LDAPInjectionVulnerability": "username",
    "MetaTagBasedInjection": "returnTo",
    "OTPVulnerability": "email",
    "PasswordResetVulnerability": "email",
    "PathTraversal": "fileName",
    "PersistentXSSInHTMLTagVulnerability": "comment",
    "SSRFVulnerability": "fileurl",
    "SampleVulnerability": "name",
    "SessionManagementVulnerability": "action",
    "UnionBasedSQLInjectionVulnerability": "id",
    "XSSInImgTagAttribute": "src",
    "XSSWithHtmlTagInjection": "value",
    "XSSWithNullBytesImgTagAttribute": "value",
}

# VulnerabilityType -> its CWE(s), from the app's own enum (cweID, wascID).
TYPE_CWES = {
    "BLIND_SQL_INJECTION": (89,),
    "ERROR_BASED_SQL_INJECTION": (89,),
    "UNION_BASED_SQL_INJECTION": (89,),
    "REFLECTED_XSS": (79,),
    "PERSISTENT_XSS": (79,),
    "DOM_BASED_XSS": (79,),
    "CLIENT_SIDE_VULNERABLE_JWT": (522,),
    "SERVER_SIDE_VULNERABLE_JWT": (347,),
    "INSECURE_CONFIGURATION_JWT": (1188,),
    "HEADER_INJECTION": (113,),
    "PATH_TRAVERSAL": (22,),
    "COMMAND_INJECTION": (77,),
    "UNRESTRICTED_FILE_UPLOAD": (434,),
    "UNCONTROLLED_RESOURCE_CONSUMPTION": (400,),
    "DENIAL_OF_SERVICE": (730,),
    "OPEN_REDIRECT_3XX_STATUS_CODE": (601,),
    "SIMPLE_SSRF": (918,),
    "BLIND_SSRF": (918,),
    "XXE": (611,),
    "WEAK_CRYPTOGRAPHIC_HASH": (327,),
    "INSECURE_CRYPTOGRAPHIC_STORAGE": (326,),
    "USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM": (330,),
    "INSECURE_DIRECT_OBJECT_REFERENCE": (639,),
    "CLICKJACKING": (1021,),
    "PLAINTEXT_PASSWORD_STORAGE": (256,),
    "WEAK_PASSWORD_HASHING": (916,),
    "USERNAME_ENUMERATION": (204,),
    "SESSION_FIXATION": (384,),
    "PREDICTABLE_SESSION_ID": (330,),
    "OBSCURED_PREDICTABLE_SESSION_ID": (330,),
    "MISSING_LOGOUT_INVALIDATION": (613,),
    "NO_LOGIN_RATE_LIMITING": (307,),
    "LDAP_INJECTION": (90,),
    "WEB_CACHE_POISONING": (349,),
    "INSECURE_DESERIALIZATION": (502,),
    "IMPROPER_AUTHORIZATION": (285,),
    "REMOTE_CODE_EXECUTION": (94,),
    "PREDICTABLE_PASSWORD_RESET_TOKEN": (330,),
    "PASSWORD_RESET_TOKEN_WITHOUT_EXPIRY": (613,),
    "REUSABLE_PASSWORD_RESET_TOKEN": (640,),
    "INSECURE_PASSWORD_RESET_LINK": (319,),
    "WEAK_RANDOM_NUMBER_GENERATION": (338,),
    "PASSWORD_RESET_TOKEN_EXPOSED_VIA_REFERRER": (200,),
    # Not a real vulnerability; excluded from scoring rather than scored as a miss.
    "SAMPLE_VULNERABILITY": (),
}

# Issue types that fire on nearly every response are dropped before scoring ("strict"). A handler
# that adds no X-Content-Type-Options is not evidence of the vulnerability a case plants, and
# leaving them in makes a scanner that reports nothing but header posture look accurate. The list
# is named, not computed from the run, so a regression that makes a NEW type go blanket is
# visible rather than silently filtered.
BLANKET_CHECK_NAMES = {
    "Frameable response (potential Clickjacking)",
    "Unencrypted communications",
    "Missing X-Content-Type-Options Header",
    "Missing Content-Security-Policy Header",
    "Content security policy: not enforced",
    "Content security policy: allows clickjacking",
}
