from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Super Secret Finder")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        issues = []

        response = baseRequestResponse.getResponse()
        responseBody = response.tostring()

        # Regular expressions to match various secrets
        regex_patterns = {
            "Cloudinary": "cloudinary://.*",
            "Firebase URL": ".*firebaseio\.com",
            "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
            "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
            "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
            "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "AWS API Key": "AKIA[0-9A-Z]{16}",
            "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
            "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
            "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
            "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
            "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
            "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
            "Picatic API Key": "sk_live_[0-9a-z]{32}",
            "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
            "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
            "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
            "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
            "Twilio API Key": "SK[0-9a-fA-F]{32}",
            "Twitter Access Token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
        }

        for regex_name, regex_pattern in regex_patterns.items():
            matches = re.findall(regex_pattern, responseBody, re.IGNORECASE)
            if matches:
                issues.extend([(regex_name, match) for match in matches])

        if issues:
            httpService = baseRequestResponse.getHttpService()
            url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
            httpMessages = [self._callbacks.applyMarkers(baseRequestResponse, None, None)]
            issueName = "Super Secret Finder: Potential Sensitive Information"
            issueDetail = ""
            for regex_name, match in issues:
                issueDetail += "\n\n\nMatched pattern: {}\nValue: {}\n\n".format(regex_name, match)

            self._callbacks.addScanIssue(CustomScanIssue(httpService, url, httpMessages, issueName, issueDetail))

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        return 0


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
