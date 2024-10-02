from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Header Guardian")
        callbacks.registerScannerCheck(self)
    
    def doPassiveScan(self, baseRequestResponse):
        issues = []

        # Extract request and response details
        analyzed_response = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        headers = analyzed_response.getHeaders()

        # Perform the checks on headers
        missing_headers = self.checkMissingHeaders(headers)
        misconfigured_headers = self.checkMisconfiguredHeaders(headers)
        toremove_headers = self.checkToRemoveHeaders(headers)
        correct_headers = self.checkCorrectHeaders(headers)

        if missing_headers or misconfigured_headers or toremove_headers:
            issues.append(self.createIssue(baseRequestResponse, missing_headers, misconfigured_headers, toremove_headers, correct_headers))

        return issues if issues else None

    def checkMissingHeaders(self, headers):
        # Define expected headers
        expected_headers = [
            'Access-Control-Allow-Origin', 'X-Content-Type-Options', 'Permissions-Policy',
            'Cross-Origin-Opener-Policy', 'X-Frame-Options', 'Referrer-Policy',
            'Strict-Transport-Security', 'Content-Security-Policy', 'X-DNS-Prefetch-Control',
            'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy', 'X-XSS-Protection'
        ]

        missing_headers = []
        for header in expected_headers:
            if not any(h.startswith(header) for h in headers):
                missing_headers.append(header)

        return missing_headers

    def checkMisconfiguredHeaders(self, headers):
        # Define expected headers and their expected values
        expected_values = {
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "0",
            "X-Content-Type-Options": "nosniff",
            "Content-Type": "charset=UTF-8",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'",
            "Access-Control-Allow-Origin": "https://yoursite.com",  
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-site",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
            "X-DNS-Prefetch-Control": "off"
        }

        # Check for misconfigured headers
        misconfigured_headers = []
        for header in headers:
            header_name = header.split(':')[0]
            if header_name in expected_values:
                current_value = header.split(':', 1)[1].strip()  # Get the value after the header name
                if current_value != expected_values[header_name]:
                    misconfigured_headers.append({
                        'name': header_name,
                        'current_value': current_value,
                        'expected_value': expected_values[header_name]
                    })

        return misconfigured_headers

    def checkCorrectHeaders(self, headers):
        # Define expected headers and their expected values
        expected_values = {
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "0",
            "X-Content-Type-Options": "nosniff",
            "Content-Type": "charset=UTF-8",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'",
            "Access-Control-Allow-Origin": "https://yoursite.com",  
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-site",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
            "X-DNS-Prefetch-Control": "off"
        }

        correct_headers = []
        for header in headers:
            header_name = header.split(':')[0]
            if header_name in expected_values:
                current_value = header.split(':', 1)[1].strip()
                if current_value == expected_values[header_name]:
                    correct_headers.append(header_name)

        return correct_headers
        
    def checkToRemoveHeaders(self, headers):
        # Define removal headers
        toremove_headers = []
        for header in headers:
            if header.startswith("Server:") or header.startswith("X-Powered-By") or \
               header.startswith("X-AspNet-Version") or header.startswith("X-AspNetMvc-Version"):
                toremove_headers.append(header)                       
        
        return toremove_headers

    def createIssue(self, baseRequestResponse, missing_headers, misconfigured_headers, toremove_headers, correct_headers):
        # Create advisory message
        details = "<b>Missing Headers:</b><br><br>"
        details += "<br>".join(missing_headers) if missing_headers else "None<br>"

        details += "<br><br><b>Misconfigured Headers:</b><br><br>"
        if misconfigured_headers:
            for header in misconfigured_headers:
                details += "<b>Header:</b> {}<br>".format(header['name'])
                details += "<b>Current Value:</b> {}<br>".format(header['current_value'])
                details += "<b>Expected Value:</b> {}<br><br>".format(header['expected_value'])
        else:
            details += "None<br>"
        
        details += "<br><b>Correct Headers:</b><br><br>"
        details += "<br>".join(correct_headers) if correct_headers else "None<br>"

        details += "<br><br><b>To Remove Headers:</b><br><br>"
        details += "<br>".join(toremove_headers) if toremove_headers else "None<br>"

        return CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
            "Header Guardian - Check Headers Issues",
            details,
            "Information",
            "Certain"
        )


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000  # Custom issue type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return "This issue stems from missing or improperly configured HTTP security headers, which play a crucial role in protecting web applications. These headers help mitigate a wide range of security vulnerabilities, including cross-site scripting (XSS), clickjacking, and information leakage, making their proper implementation essential for safeguarding user data and maintaining application integrity."

    def getRemediationBackground(self):
    	return (
        "Ensure all security-related HTTP headers are configured correctly according to OWASP best practices. "
        "For more details, refer to the <a href='https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'>"
        "OWASP HTTP Headers Cheat Sheet</a>."
    )

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
