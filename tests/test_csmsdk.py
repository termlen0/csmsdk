#!/usr/bin/env python
import pytest
import csmsdk.csmsdk as csm
#GLOBALS
URL = "https://ccsmghoh01.gis.corp.ge.com"
UNAME = "sec_automation"
PWORD = "fwautomation"
CONTEXT = "DEVfvMUSashdc01-1401"

def test_login():
    ''' Validate that the user can login and logout successfully'''
    mycsm = csm.Csm(url=URL, username=UNAME, password=PWORD)
    resp = mycsm.login()
    assert "logged in" in resp
    resp = mycsm.logout()
    assert "logged out" in resp


def test_acllist():
    '''Given the access-list name, show the access-list'''
    #CSM_FW_ACL_OUTSIDE
    mycsm = csm.Csm(url=URL, username=UNAME, password=PWORD)
    resp = mycsm.login()

    resp = mycsm.logout()
    assert "logged out" in resp
    pass

def test_acladd():
    '''Given the access-list name, insert an ACE to the list'''
    pass

def test_aclremove():
    '''Given the acl name, and tuple, remove the entry'''
    pass
