#!/usr/bin/env python
import os
import requests
import xml.etree.ElementTree as etree
from jinja2 import Environment, FileSystemLoader
import re
import logging
requests.packages.urllib3.disable_warnings()


class LoginException(BaseException):
    pass


class CsmException(BaseException):
    pass


class Csm(object):

    '''Object instances will represent a CSM api session'''
    def __init__(self, context_name='None', username='guest', password='guest',
                 url='None', logdir="/tmp/"):
        self.context = context_name
        self.username = username
        self.password = password
        self.csm = url
        self.cookie =''
        #Create the logdir
        os.makedirs(logdir, exist_ok=True)
        logging.basicConfig(filename=logdir + "csmsdk.log",
                            level=logging.DEBUG)
        logging.info("INFO: Initialized CSM object....")

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
        # Check whether the config backup dir exists - Create if not
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
        logging.debug("DEBUG: {} cookie, logged in".format(self.cookie))
        response = self.session.post(url=self.csm + path, data=payload,
                                     headers=headers, verify=False)
        if response.status_code != 200:
            logging.debug("DEBUG: {} \n".format(response.text))
            logging.debug("DEBUG: session cookie -  {} ".format(self.cookie))
            self.logout()
            raise CsmException(
                "Error retriving the config : {}".format(response.status_code))
        else:
            root = etree.fromstring(response.text)
            try:
                for child in root:
                    if child.tag == 'device':
                        for gchild in child:
                            if gchild.tag == 'fullConfig':
                                try:
                                    with open(config_file, "+w") as f:
                                        f.write(gchild.text)
                                except:
                                    logging.debug(
                                        "Error writing backup to file")
            except:
                logging.debug("Error traversing the dom")

    def showpolicy(self, policyname='None'):
        """Given the policy name, return the shared policy(xml) as a string.
        It is up to the endpoint consumer to parse it"""
        # STEP 1: Collect the "policy type"
        # STEP 1a: Collect the GID uing the context name
        path = "/nbi/configservice/getDeviceListByType"
        payload = """<?xml version="1.0" encoding="UTF-8"?>
        <n:deviceListByCapabilityRequest xmlns:n="csm">
        <protVersion>1.0</protVersion>
        <reqId>123</reqId>
        <deviceCapability>firewall</deviceCapability>
        </n:deviceListByCapabilityRequest> """
        logging.info("INFO: Collecting the GID...")
        headers = {'Content-type': 'text/xml'}
        logging.debug("DEBUG: {} cookie, logged in".format(self.cookie))
        response = self.session.post(url=self.csm + path, data=payload,
                                     headers=headers, verify=False)
        if response.status_code != 200:
            logging.debug("DEBUG: {} \n".format(response.text))
            logging.debug("DEBUG: session cookie -  {} ".format(self.cookie))
            self.logout()
            raise CsmException(
                "Error retrieving the GID : {}".format(response.status_code))
        else:
            try:
                root = etree.fromstring(response.text)
                for node in root.findall('deviceId'):
                    if node.find('deviceName').text == self.context:
                        gid =node.find('gid').text
                logging.info("INFO: GID identified - {}".format(gid))
            except:
                self.logout()
                logging.error("ERROR: Unable to collect the gid..")
        # STEP 1b: Collect the "policy type" uing the GID
        path = "/nbi/configservice/getPolicyListByDeviceGID"
        payload = ("""<?xml version="1.0" encoding="UTF-8"?>
        <n:policyListByDeviceGIDRequest xmlns:n="csm">
        <protVersion>1.0</protVersion>
        <reqId>123</reqId>
        <gid>{}</gid>
        </n:policyListByDeviceGIDRequest>""").format(gid)
        logging.info("INFO: Collecting the policyType...")
        headers = {'Content-type': 'text/xml'}
        logging.debug("DEBUG: {} cookie, logged in".format(self.cookie))
        response = self.session.post(url=self.csm + path, data=payload,
                                     headers=headers, verify=False)
        if response.status_code != 200:
            logging.debug("DEBUG: {} \n".format(response.text))
            logging.debug("DEBUG: session cookie -  {} ".format(self.cookie))
            self.logout()
            raise CsmException(
                "Error retrieving the policytype : {}".format(
                    response.status_code))
        else:
            try:
                root = etree.fromstring(response.text)
                for node in root.findall('policyList'):
                    for child in node:
                        if child.find('name').text == policyname:
                            policytype = child.find('type').text
                logging.info("INFO: The policy type is {}".format(policytype))
            except:
                self.logout()
                logging.error("ERROR: Unable to collect the policytype")
        # STEP 2: Collect the policy info
        path = "/nbi/configservice/getPolicyConfigByName"
        payload = ("""<?xml version="1.0" encoding="UTF-8"?>
        <n:policyConfigByNameRequest xmlns:n="csm">
        <protVersion>1.0</protVersion>
        <reqId>123</reqId>
        <name>{}</name>
        <policyType>{}</policyType>
        </n:policyConfigByNameRequest>""").format(policyname, policytype)
        logging.info("INFO: Collecting the policy details...")
        headers = {'Content-type': 'text/xml'}
        logging.debug("DEBUG: {} cookie, logged in".format(self.cookie))
        response = self.session.post(url=self.csm + path, data=payload,
                                     headers=headers, verify=False)
        if response.status_code != 200:
            logging.debug("DEBUG: {} \n".format(response.text))
            logging.debug("DEBUG: session cookie -  {} ".format(self.cookie))
            self.logout()
            raise CsmException(
                "Error retrieving the policytype : {}".format(
                    response.status_code))
        else:
            try:
                root = etree.fromstring(response.text)
                logging.info("INFO: Policy collected....")
                return etree.tostring(root.find('policy'), encoding="unicode")
            except:
                self.logout()
                logging.error("ERROR: Unable to retrieve the policy")


    def getpolicyobj(self, *args):
        """Given the gid, return the details of the policy object.
        It is up to the endpoint consumer to parse it"""
        # Use Jinja2 to generate the xml payload
        # Set up the directory, where to find the template
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        template_loader = FileSystemLoader(template_dir)
        template_env = Environment(loader=template_loader)
        # Get the jinja2 xml template
        xml_template = template_env.get_template('getpolicyobj.j2')
        # Generate the payload
        arg_dict = {'gids': args}
        payload = xml_template.render(arg_dict)
        path = "/nbi/configservice/getPolicyObjectByGID"
        logging.info("INFO: Collecting the object details...")
        headers = {'Content-type': 'text/xml'}
        logging.debug("DEBUG: {} cookie, logged in".format(self.cookie))
        response = self.session.post(url=self.csm + path, data=payload,
                                     headers=headers, verify=False)
        if response.status_code != 200:
            logging.debug("DEBUG: {} \n".format(response.text))
            logging.debug("DEBUG: session cookie -  {} ".format(self.cookie))
            self.logout()
            raise CsmException(
                "Error retrieving the policy details : {}".format(
                    response.status_code))
        else:
            try:
                root = etree.fromstring(response.text)
                logging.info(
                    "INFO:Entire Details for GIDs collected..")
                return etree.tostring(root.find('./policyObject'),
                                          encoding="unicode")
            except BaseException as e:
                self.logout()
                logging.error("ERROR: Unable to collect the policy details..")
                logging.error(e)
