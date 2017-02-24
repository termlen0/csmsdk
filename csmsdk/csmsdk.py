#!/usr/bin/env python
import os
import requests
import xml.etree.ElementTree as etree
from xml.etree.ElementTree import XML
import re
import logging
requests.packages.urllib3.disable_warnings()

logging.basicConfig(filename="/tmp/csmsdk.log", level=logging.DEBUG)


class LoginException(BaseException):
    pass

class CsmException(BaseException):
    pass

class Csm(object):

    '''Object instances will represent a CSM api session'''
    def __init__(self, context_name='None', username='guest', password='guest',
                 url='None'):
        logging.info("INFO: Initialized CSM object....")
        self.context = context_name
        self.username = username
        self.password = password
        self.csm = url
        self.cookie =''

    def login(self):
        path = "/nbi/login"
        payload = ("""<?xml version="1.0" encoding="UTF-8"?>
        <csm:loginRequest xmlns:csm="csm">
        <protVersion>1.0</protVersion>
        <reqId>123</reqId>
        <username>{}</username>
        <password>{}</password>
        </csm:loginRequest> """).format(self.username, self.password)
        headers = {'Content-type': 'text/xml'}
        self.session = requests.Session()
        response = self.session.post(url=self.csm + path, data=payload,
                                     headers=headers, verify=False)
        logging.debug("DEBUG: Post response")
        if response.status_code != 200:
            #User is already logged in
            '''
            Login to the NB API failed. You are not allowed to log in again,
            because a user with the same user ID has already logged in to Cisco
            Security Manager through the NB API. Please wait until the other
            user has logged out from the NB API
            '''
            pattern = re.compile(
                "user with the same user ID has already logged in")
            if pattern.search(response.text) != None:
                return("{}, already logged in".format(self.username))
            else:
                raise LoginException
        else:
            self.cookie = response.headers['Set-Cookie'].split(';')[0].split(
                '=')[1]
            logging.debug("INFO: {} cookie, logged in".format(self.cookie))
            return("{},logged in".format(self.username))


    def logout(self):
        path = "/nbi/logout"
        payload = """<?xml version="1.0" encoding="UTF-8"?>
        <csm:logoutRequest xmlns:csm="csm">
        <protVersion>1.0</protVersion>
        <reqId>123</reqId>
        </csm:logoutRequest> """
        ''' As long as the same session is being used to log out, the session
        cookie will persist '''
        response = self.session.post(url=self.csm + path, data=payload,
                                     verify=False)
        if response.status_code != 200:
            return(response)
        else:
            logging.info(
                "INFO: {} successfully logged out..".format(self.username))
            return("{} successfully logged out".format(self.username))

    def showrun(self, confpath="/tmp"):
        '''Method to get the running config of the device by context name'''
        #Check whether the config backup dir exists - Create if not
        os.makedirs(confpath, exist_ok=True)
        config_file = confpath + self.context
        # Execute the API call
        path = "/nbi/configservice/getDeviceConfigByName"
        payload = ("""<?xml version="1.0" encoding="UTF-8"?>
        <n:deviceConfigByNameRequest xmlns:n="csm">
        <protVersion>1.0</protVersion>
        <reqId>123</reqId>
        <name>{}</name>
        </n:deviceConfigByNameRequest> """).format(self.context)
        headers = {'Content-type': 'text/xml'}
        logging.debug("DEBUG: {} cookie, logged in".format(self.context))
        response = self.session.post(url=self.csm + path, data=payload,
                                     headers=headers, verify=False)
        if response.status_code != 200:
            logging.debug("DEBUG: {} \n".format(response.text))
            logging.debug("DEBUG: session cookie -  {} ".format(self.cookie))
            raise CsmException(
                "Error retriving the config : {}".format(response.status_code))
        else:
            root = etree.fromstring(response.text)
            try:
                for child in root:
                    if child.tag == 'fullConfig':
                        try:
                            with open(config_file, "+w") as f:
                                f.write(child.text)
                        except:
                            logging.debug("Error writing backup to file")
            except:
                logging.debug("Error traversing the dom")

            assert 0


    def showacl(self, aclname='None'):
        path = "/nbi/configservice/getPolicyConfigByName"
        payload = """<?xml version="1.0" encoding="UTF-8"?>

        """
