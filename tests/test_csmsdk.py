#!/usr/bin/env python
import pytest
import csmsdk.csmsdk as csm
#GLOBALS
URL = "https://ccsmghoh01.gis.corp.ge.com"
UNAME = "sec_automation"
PWORD = "fwautomation"
CONTEXT = "DEVfvMUSashdc01-1401"
LOGDIR = "/tmp/csmsdklogs/"
CONFIGDIR = "/tmp/csmsdkconf/"


def test_login():
    ''' Validate that the user can login and logout successfully'''
    mycsm = csm.Csm(url=URL, username=UNAME, password=PWORD, logdir=LOGDIR)
    resp = mycsm.login()
    assert "logged in" in resp
    resp = mycsm.logout()
    assert "logged out" in resp


def test_getconfig():
    """Given the context, get the running config"""
    mycsm = csm.Csm(url=URL, username=UNAME, password=PWORD, logdir=LOGDIR,
                    context_name=CONTEXT)
    mycsm.login()
    mycsm.showrun(confpath=CONFIGDIR)
    mycsm.logout()


def test_acllist():
    '''Given the access-list name, show the access-list'''
    # CSM_FW_ACL_OUTSIDE
    mycsm = csm.Csm(url=URL, username=UNAME, password=PWORD, logdir=LOGDIR,
                    context_name=CONTEXT)
    mycsm.login()
    xml_resp = mycsm.showpolicy(policyname='DEV_CLOUD_TEST_POLICY')
    mycsm.logout()
    assert "policy" in xml_resp

def test_getpolicyobj():
    """Given the GID of a policy object, get its details"""
    # The GID of the object is obtained by parsing the output of the showpolicy
    # for instance.
    # The idea behind this method, is to provide a means to validate the current
    # values of policy objects; can be used for validation, before adding a new
    # policy
    mycsm = csm.Csm(url=URL, username=UNAME, password=PWORD, logdir=LOGDIR,
                    context_name=CONTEXT)
    mycsm.login()
    xml_resp = mycsm.getpolicyobj('00000000-0000-0000-0000-017179872090','test')
    assert 0
    mycsm.logout()


def test_acladd():
    '''Given the access-list name, insert an ACE to the list'''
    pass


def test_aclremove():
    '''Given the acl name,  ggggggggbbvvvvvvnnnnnng hvhvhtand tuple, remove the entry'''
    pass
