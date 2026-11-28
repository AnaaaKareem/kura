# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 0 |
| Low | 1 |
| Informational | 7 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Info | Informational | https://localhost | Percentage of responses with status code 2xx | 59 % |
| Info | Informational | https://localhost | Percentage of responses with status code 3xx | 21 % |
| Info | Informational | https://localhost | Percentage of responses with status code 4xx | 18 % |
| Info | Informational | https://localhost | Percentage of endpoints with content type application/javascript | 8 % |
| Info | Informational | https://localhost | Percentage of endpoints with content type image/svg+xml | 2 % |
| Info | Informational | https://localhost | Percentage of endpoints with content type text/css | 8 % |
| Info | Informational | https://localhost | Percentage of endpoints with content type text/html | 80 % |
| Info | Informational | https://localhost | Percentage of endpoints with method GET | 77 % |
| Info | Informational | https://localhost | Percentage of endpoints with method POST | 22 % |
| Info | Informational | https://localhost | Count of total endpoints | 35    |
| Info | Informational | https://localhost | Percentage of slow responses | 40 % |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Private IP Disclosure | Low | 1 |
| Authentication Request Identified | Informational | 1 |
| Information Disclosure - Sensitive Information in URL | Informational | 1 |
| Information Disclosure - Suspicious Comments | Informational | 11 |
| Non-Storable Content | Informational | Systemic |
| Session Management Response Identified | Informational | 11 |
| Storable and Cacheable Content | Informational | 2 |
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 1 |




## Alert Detail



### [ Private IP Disclosure ](https://www.zaproxy.org/docs/alerts/2/)



##### Low (Medium)

### Description

A private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for example, ip-10-0-56-78) has been found in the HTTP response body. This information might be helpful for further attacks targeting internal systems.

* URL: https://localhost/account/sessions/
  * Node Name: `https://localhost/account/sessions/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `172.28.10.128`
  * Other Info: `172.28.10.128
`


Instances: 1

### Solution

Remove the private IP address from the HTTP response body. For comments, use JSP/ASP/PHP comment instead of HTML/JavaScript comment which can be seen by client browsers.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc1918 ](https://datatracker.ietf.org/doc/html/rfc1918)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: https://localhost/login/
  * Node Name: `https://localhost/login/ ()(csrfmiddlewaretoken,email,password)`
  * Method: `POST`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=email
userValue=zaproxy@example.com
passwordParam=password
referer=https://localhost/login/
csrfToken=csrfmiddlewaretoken`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Information Disclosure - Sensitive Information in URL ](https://www.zaproxy.org/docs/alerts/10024/)



##### Informational (Medium)

### Description

The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.

* URL: https://localhost/schedules/%3Fcourse=ab70573f-85a7-4240-bb9d-1fe4b6404ef0&day=monday&session_type=lecture
  * Node Name: `https://localhost/schedules/ (course,day,session_type)`
  * Method: `GET`
  * Parameter: `session_type`
  * Attack: ``
  * Evidence: `session_type`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: session
session_type`


Instances: 1

### Solution

Do not pass sensitive information in URIs.

### Reference



#### CWE Id: [ 598 ](https://cwe.mitre.org/data/definitions/598.html)


#### WASC Id: 13

#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Medium)

### Description

The response appears to contain suspicious comments which may help an attacker.

* URL: https://localhost/
  * Node Name: `https://localhost/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/account/privacy/
  * Node Name: `https://localhost/account/privacy/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/account/sessions/
  * Node Name: `https://localhost/account/sessions/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/attendance/history/
  * Node Name: `https://localhost/attendance/history/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/courses/
  * Node Name: `https://localhost/courses/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/grades/my/
  * Node Name: `https://localhost/grades/my/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/mfa/confirm/%3Fnext=%252Fpasskeys%252F
  * Node Name: `https://localhost/mfa/confirm/ (next)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/password/change/
  * Node Name: `https://localhost/password/change/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/schedules/
  * Node Name: `https://localhost/schedules/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/static/js/theme.6b98b0d9a05d.js
  * Node Name: `https://localhost/static/js/theme.6b98b0d9a05d.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// Loaded from an external file be`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 2 times, the first in likely comment: "// Loaded from an external file because the Content Security Policy blocks inline scripts.", see evidence field for the suspicious comment/snippet.`
* URL: https://localhost/transcript/
  * Node Name: `https://localhost/transcript/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<!-- Signed-in user summary at the bott`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "<!-- Signed-in user summary at the bottom of the sidebar. -->", see evidence field for the suspicious comment/snippet.`


Instances: 11

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 615 ](https://cwe.mitre.org/data/definitions/615.html)


#### WASC Id: 13

#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: https://localhost/
  * Node Name: `https://localhost/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: https://localhost/account/sessions/
  * Node Name: `https://localhost/account/sessions/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: https://localhost/courses/
  * Node Name: `https://localhost/courses/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: https://localhost/passkeys/
  * Node Name: `https://localhost/passkeys/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: https://localhost/sitemap.xml
  * Node Name: `https://localhost/sitemap.xml`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``

Instances: Systemic


### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (Medium)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: https://localhost/
  * Node Name: `https://localhost/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/account/privacy/
  * Node Name: `https://localhost/account/privacy/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/account/sessions/
  * Node Name: `https://localhost/account/sessions/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/attendance/history/
  * Node Name: `https://localhost/attendance/history/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/courses/
  * Node Name: `https://localhost/courses/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/grades/my/
  * Node Name: `https://localhost/grades/my/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/mfa/confirm/%3Fnext=%252Fpasskeys%252F
  * Node Name: `https://localhost/mfa/confirm/ (next)`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/passkeys/
  * Node Name: `https://localhost/passkeys/`
  * Method: `GET`
  * Parameter: `messages`
  * Attack: ``
  * Evidence: `messages`
  * Other Info: `cookie:messages
cookie:__Host-kura_session`
* URL: https://localhost/password/change/
  * Node Name: `https://localhost/password/change/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/schedules/
  * Node Name: `https://localhost/schedules/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`
* URL: https://localhost/transcript/
  * Node Name: `https://localhost/transcript/`
  * Method: `GET`
  * Parameter: `__Host-kura_session`
  * Attack: ``
  * Evidence: `__Host-kura_session`
  * Other Info: `cookie:__Host-kura_session
cookie:__Host-kura_csrftoken`


Instances: 11

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: https://localhost/static/css/bootstrap.min.6a7df65a8257.css
  * Node Name: `https://localhost/static/css/bootstrap.min.6a7df65a8257.css`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=2592000`
  * Other Info: ``
* URL: https://localhost/static/js/theme-init.46cf6f828b59.js
  * Node Name: `https://localhost/static/js/theme-init.46cf6f828b59.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=2592000`
  * Other Info: ``


Instances: 2

### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ User Controllable HTML Element Attribute (Potential XSS) ](https://www.zaproxy.org/docs/alerts/10031/)



##### Informational (Low)

### Description

This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.

* URL: https://localhost/mfa/confirm/%3Fnext=%252Fpasskeys%252F
  * Node Name: `https://localhost/mfa/confirm/ (next)`
  * Method: `GET`
  * Parameter: `next`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost/mfa/confirm/?next=%2Fpasskeys%2F

appears to include user input in:
a(n) [a] tag [href] attribute

The user input found was:
next=/passkeys/

The user-controlled value was:
/passkeys/`


Instances: 1

### Solution

Validate all input and sanitize output it before writing to any HTML attributes.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)


#### CWE Id: [ 20 ](https://cwe.mitre.org/data/definitions/20.html)


#### WASC Id: 20

#### Source ID: 3


