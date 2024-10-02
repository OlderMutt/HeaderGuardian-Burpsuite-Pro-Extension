# Header Guardian

**Header Guardian** is a Burp Suite extension designed to enhance the security of web applications by identifying missing, misconfigured, and unnecessary HTTP security headers. Properly configured security headers are critical in protecting against vulnerabilities like cross-site scripting (XSS), clickjacking, and information leakage.

## Features
- **Missing Headers Detection**: Identifies critical security headers that are missing from HTTP responses.
- **Misconfigured Headers Detection**: Reports headers that are present but not properly configured according to OWASP best practices.
- **Correct Headers Reporting**: Lists headers that are properly configured.
- **Unnecessary Headers Detection**: Detects headers that should be removed, such as `Server` and `X-Powered-By`.

## How It Works
Header Guardian performs passive scanning by analyzing HTTP responses and checking for the presence and correctness of important security headers. It generates detailed reports on:
- **Missing Headers**: Security headers that should be added.
- **Misconfigured Headers**: Headers that have incorrect or insecure values.
- **Correct Headers**: Headers that are properly configured.
- **Headers to Remove**: Headers that reveal unnecessary information about the server or application environment.

## Installation
1. Download or clone this repository.
2. In Burp Suite, go to the Extender tab and click on **Add**.
3. Select the `HeaderGuardian.py` file and click **Next**.
4. The extension will be loaded and ready for use.

## Usage
1. Once the extension is installed, it will automatically scan HTTP responses during passive scans.
2. Results can be found in the **Issues** tab, where the extension will provide details about:
   - Missing headers.
   - Misconfigured headers and their expected values.
   - Correct headers.
   - Headers that should be removed.

## Headers Checked
### Expected Headers:
- `Access-Control-Allow-Origin`
- `X-Content-Type-Options`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `X-Frame-Options`
- `Referrer-Policy`
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-DNS-Prefetch-Control`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Resource-Policy`
- `X-XSS-Protection`

### Misconfigured Header Values:
- `X-Frame-Options`: `DENY`
- `X-XSS-Protection`: `0`
- `X-Content-Type-Options`: `nosniff`
- `Content-Type`: `charset=UTF-8`
- `Referrer-Policy`: `strict-origin-when-cross-origin`
- `Strict-Transport-Security`: `max-age=63072000; includeSubDomains; preload`
- `Content-Security-Policy`: `default-src 'self'`
- `Access-Control-Allow-Origin`: `https://yoursite.com`
- `Cross-Origin-Opener-Policy`: `same-origin`
- `Cross-Origin-Embedder-Policy`: `require-corp`
- `Cross-Origin-Resource-Policy`: `same-site`
- `Permissions-Policy`: `geolocation=(), camera=(), microphone=()`
- `X-DNS-Prefetch-Control`: `off`

### Headers to Remove:
- `Server`
- `X-Powered-By`
- `X-AspNet-Version`
- `X-AspNetMvc-Version`

License
-------

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

Contributing
------------

Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request.

Contact
-------

For any questions or issues, please contact oldermutt@proton.me

Acknowledgments
---------------

-   This extension follows recommendations for HTTP security headers from OWASP. For more details, refer to the [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
