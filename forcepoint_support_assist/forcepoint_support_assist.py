from __future__ import with_statement
import os
import socket
import win32evtlog
import sys
from datetime import datetime
import subprocess
import shutil
import pyodbc
import csv
import win32wnet
import servicemanager
import _winreg
import ctypes
import zipfile
import win32security
import win32con
from _winreg import *
import xml.etree.ElementTree as ET
import logging
import win32com.client
import re
import time
print('SVOS 1.17')

class disable_file_system_redirection:
    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection

    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)


disable_file_system_redirection().__enter__()

class enable_file_system_redirection:
    _enable = ctypes.windll.kernel32.Wow64EnableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection

    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._enable(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)


def getEIPpath():
    exists = True
    try:
        hKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, 'Software\\Wow6432Node\\Websense\\EIP Infra')
        result = _winreg.QueryValueEx(hKey, 'INSTALLDIR')
        return result[0]
    except OSError(e):
        exists = False

    try:
        hKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, 'Software\\Wow6432Node\\Websense\\EIP Infra')
    except OSError(e):
        print('Not a Triton Management Server')


EIP = getEIPpath()
TMP = os.getenv('TMP', 'NONE')
dsshome = os.getenv('DSS_HOME', 'NONE')
print('AP-DATA Detected.  Proceeding with data collection.')
if dsshome == 'NONE':
    servicemanager.LogInfoMsg('No AP-DATA Manager Detected.  Stopping')
    sys.exit()
path = '%s\\SVOS' % TMP
if os.path.exists(path):
    shutil.rmtree(path)
    os.mkdir(path)
else:
    os.mkdir(path)
SYSROOT = os.getenv('SystemRoot', 'none')
TMP = os.getenv('TMP', 'NONE')
LOGS = '%s\\Logs\\' % dsshome
DSS = '%s\\SVOS\\DSSLogs' % TMP
JETTYHOME = os.getenv('JETTY_HOME', 'NONE')
RRDB = '%s\\ResourceResolver\\ResourceResolverServerMaster.db' % dsshome
RR = '%s\\SVOS\\RR.db' % TMP
DLPXML = '%s\\tomcat\\conf\\Catalina\\localhost\\dlp.xml' % dsshome
DLPCONF = '%s\\SVOS\\DLP.xml' % TMP
CATPROP = '%s\\tomcat\\conf\\catalina.properties' % dsshome
CATALINAPROPERTIES = '%s\\SVOS\\catalina.properties' % TMP
EIPSET = '%s\\EIPSettings.xml' % EIP
EIPXML = '%s\\SVOS\\EIPSettings.xml' % TMP
HTTPC = '%s\\apache\\conf\\httpd.conf' % dsshome
HTTPconf = '%s\\SVOS\\httpd.conf' % TMP
HTTPSSLC = '%s\\apache\\conf\\extra\\httpd-ssl.conf' % dsshome
HTTPSconf = '%s\\SVOS\\httpd-ssl.conf' % TMP
EP_CLUSTER_KEY = '%s\\keys\\ep_cluster.key' % dsshome
EPCKEY = '%s\\SVOS\\ep_cluster.key' % TMP
Machine_KEY = '%s\\keys\\machine.key' % dsshome
MAC_KEY = '%s\\SVOS\\machine.key' % TMP
APPLOG = '%s\\System32\\winevt\\Logs\\Application.evtx' % SYSROOT
SYSLOG = '%s\\System32\\winevt\\Logs\\System.evtx' % SYSROOT
APPLICATION = '%s\\SVOS\\application.evtx' % TMP
SYSTEM = '%s\\SVOS\\system.evtx' % TMP
CONFSTORE = '%s\\ConfigurationStore\\' % dsshome
CONFIGSTORE = '%s\\SVOS\\ConfigurationStore' % TMP
BATCHSERVLF = '%sData-Batch-Server\\service-container\\container\\logs\\service_logs\\' % dsshome
BATCHSERV = '%s\\service-container\\container\\logs\\' % JETTYHOME
DBATCHLOG = '%s\\SVOS\\BatchServerlogs\\' % TMP
TOM = '%s\\tomcat\\logs\\' % dsshome
TOMCAT = '%s\\SVOS\\TomcatLogs\\' % TMP
EPSERVERCONF = '%sEndPointServer.config.xml' % dsshome
EPSERVERCONFIG = '%s\\SVOS\\EndPointServer.config.xml' % TMP
HOSTNAME = socket.gethostname()
userprofile = os.getenv('USERPROFILE', 'NONE')
FPARCHIVE = datetime.now().strftime(userprofile + '\\Desktop\\SVOS_' + '_' + HOSTNAME + '_%Y%m%d-%H%M%S.zip')
DIR = '%s\\SVOS' % TMP
File = 'logfile.log'
FULL_PATH = os.path.join(DIR, File)
CACER = '%s\\ca.cer' % dsshome
KEYS = '%s\\keys\\' % dsshome
CONF = '%s\\conf\\' % dsshome
CANON = '%s\\canonizer.config.xml' % dsshome
CANONconf = '%s\\SVOS\\canonizer.config.xml' % TMP
EXTRACTconf = '%s\\extractor.config.xml' % dsshome
EXTconf = '%s\\SVOS\\extractor.config.xml' % TMP
EXTRACTLINconf = '%s\\extractorlinux.config.xml' % dsshome
EXTLINconf = '%s\\SVOS\\extractorlinux.config.xml' % TMP
EIPTOMLOGS = '%s\\tomcat\\logs\\' % EIP
EIPTOMLOGDIR = '%s\\SVOS\\EIPTOMLOGS\\' % TMP
EIPLOGS = '%s\\logs\\' % EIP
EIPLOGDIR = '%s\\SVOS\\EIPLOGS\\' % TMP
JETTYXML = '%s\\service-container\\container\\etc\\jetty.xml' % JETTYHOME
EIPapachelogs = '%s\\apache\\logs\\' % EIP
EIPAPACHELOGS = '%s\\SVOS\\EIPapachelogs\\' % TMP
APACHELOGS = '%sapache\\logs' % dsshome
DSSAPACHELOGS = '%s\\SVOS\\DSSapachelogs\\' % TMP
DBATCHSERV = '%s\\logs\\' % JETTYHOME
DBATCHLOG801 = '%s\\SVOS\\BatchServerlog801\\' % TMP
MBMQ = '%s\\MessageBroker\\data\\activemq.log' % dsshome
ACMQ = '%s\\SVOS\\activemq.log' % TMP
MBAU = '%s\\MessageBroker\\data\\audit.log' % dsshome
MBAUD = '%s\\SVOS\\audit.log' % TMP
SERLOG = '%s\\MessageBroker\\data\\service_logs\\' % dsshome
SERVLOG = '%s\\SVOS\\MessageBrokerSvclogs\\' % TMP
OCR = '%s\\OCRServer.config.xml' % dsshome
OCRConfig = '%s\\SVOS\\OCRServer.config.xml' % TMP
FileEncryptor = '%s\\FileEncryptor.log' % dsshome
FE = '%s\\SVOS\\FileEncryptor.log' % TMP
PEP = '%s\\PolicyEngine.policy.xml' % dsshome
PEPS = '%s\\SVOS\\PolicyEngine.policy.xml' % TMP
PEPB = '%s\\PolicyEngine.policy.xml.bak' % dsshome
PEPBS = '%s\\SVOS\\PolicyEngine.policy.xml.bak' % TMP
AC = '%s\\allcerts.cer' % dsshome
ACS = '%s\\SVOS\\allcerts.cer' % TMP
CA = '%s\\ca.cer' % dsshome
CAS = '%s\\SVOS\\ca.cer' % TMP
HCK = '%s\\HostCert.key' % dsshome
HCKS = '%s\\SVOS\\HostCert.key' % TMP

class Logger(object):

    def __init__(self, filename='Default.log'):
        self.terminal = sys.stdout
        self.log = open(filename, 'a')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)


sys.stdout = Logger(FULL_PATH)
shutil.copytree(LOGS, DSS)
print('Copying DSS home')
shutil.copy(RRDB, RR)
print('Copying Resource Resolver')
if os.path.isfile(DLPXML):
    shutil.copy(DLPXML, DLPCONF)
    print('Copying DLP.xml')
else:
    print('Not a Triton Manager, No dlp.xml, moving on.')
if os.path.isdir(TOM):
    shutil.copy(CATPROP, CATALINAPROPERTIES)
    print('Copying catalina.properties')
else:
    print('Not a Triton Manager, No catalina.properties, moving on.')
if os.path.isfile(EIPSET):
    shutil.copy(EIPSET, EIPXML)
    print('Copying EIP Settings')
else:
    print('Not a Triton Manager, No EIPSettings, moving on.')
if os.path.isdir(BATCHSERV):
    shutil.copytree(BATCHSERV, DBATCHLOG)
    print('Copying Batch server logs')
else:
    print('Not a Triton Manager, or a legacy manager. No Batch Server, moving on.')
shutil.copy(HTTPC, HTTPconf)
print('Copying http config')
shutil.copy(HTTPSSLC, HTTPSconf)
print('Copying https config')
shutil.copy(EP_CLUSTER_KEY, EPCKEY)
print('Coying EP_Cluster.key')
shutil.copy(Machine_KEY, MAC_KEY)
print('Copying machine.key')
shutil.copy(APPLOG, APPLICATION)
print('Copying Windows Application Event Logs')
shutil.copy(SYSLOG, SYSTEM)
print('Copying Windows System Event Logs')
shutil.copytree(CONFSTORE, CONFIGSTORE)
print('Copying ConfigurationStore')
print('Copying canonizer config')
shutil.copy(CANON, CANONconf)
print('Copying extractor config')
shutil.copy(EXTRACTconf, EXTconf)
print('Copying extractorlinux config')
shutil.copy(EXTRACTLINconf, EXTLINconf)
if os.path.isdir(TOM):
    shutil.copytree(TOM, TOMCAT)
    print('Copying Tomcat logs')
else:
    print('Not a Triton Manager, No Tomcat logs, moving on.')
shutil.copy(EPSERVERCONF, EPSERVERCONFIG)
print('Copying EndPointServer Configuration')
if os.path.isfile(EIPSET):
    shutil.copytree(EIPTOMLOGS, EIPTOMLOGDIR)
    print('Copying EIP Tomcat logs')
else:
    print('Not a Triton Manager, No Tomcat logs, moving on.')
if os.path.isfile(EIPSET):
    shutil.copytree(EIPLOGS, EIPLOGDIR)
    print('Copying EIP Install logs')
else:
    print('Not a Triton Manager, No Tomcat logs, moving on.')
if os.path.isdir(EIPapachelogs):
    shutil.copytree(EIPapachelogs, EIPAPACHELOGS)
    print('Copying EIP Apache logs')
else:
    print('Not a Triton Manager, No Tomcat logs, moving on.')
if os.path.isfile(FileEncryptor):
    shutil.copy(FileEncryptor, FE)
    print('Copying File Encryptor log')
else:
    print('Not a Triton Manager, or a legacy manager. No file encryptor log, moving on.')
print('Copying DSS apache logs')
shutil.copytree(APACHELOGS, DSSAPACHELOGS)
if os.path.isdir(DBATCHSERV):
    shutil.copytree(DBATCHSERV, DBATCHLOG801)
    print('Copying Batch server logs')
else:
    print('Not a Triton Manager, No Tomcat logs, moving on.')
if os.path.isdir(SERLOG):
    shutil.copytree(SERLOG, SERVLOG)
    print('Copying Message Broker Service logs')
else:
    print('Not a Triton Manager, No Tomcat logs, moving on.')
if os.path.isfile(MBAU):
    shutil.copy(MBAU, MBAUD)
    print('Copying Message Broker Audit log')
else:
    print('Not a Triton Manager, No Tomcat logs, moving on.')
if os.path.isfile(MBMQ):
    shutil.copy(MBMQ, ACMQ)
    print('Copying Message Broker activemq log')
else:
    print('Not a Triton Manager, No Tomcat logs, moving on.')
if os.path.isfile(OCR):
    shutil.copy(OCR, OCRConfig)
    print('Copying OCR server config')
else:
    print('Not a secondary server. No OCR config file, moving on')
shutil.copy(PEP, PEPS)
print('Copying policyenginge.policy.xml')
shutil.copy(PEPB, PEPBS)
print('Copying policyenginge.policy.xml.bak')
shutil.copy(AC, ACS)
print('Copying allcerts.cer')
shutil.copy(CA, CAS)
print('Copying ca.cer')
shutil.copy(HCK, HCKS)
print('Copying HostCert.key')

'''
Parse EIPSettings.xml for the following elements within the <LogDB></LogDB> tags:

SQLSERVER = <Host></Host> value
SQLINSTANCE = <InstanceName></InstanceName> value
SQLUSER = <Username></Username> value
SQLDOMAIN = <Domain></Domain> value
SQLPASS = <Password></Password> value

In Forcepoint DLP v8.5.2, EIPSettings.xml is missing values for the following elements:
<Username>
<Domain>
<Password>

The logic below does not handle scenarios when the above values are missing.
'''
if os.path.exists(EIPSET):
    tree = ET.parse(EIPSET)
    content = tree.getroot()
    for LogDB in content.findall('LogDB'):
        SQLSERVER = str(LogDB.find('Host').text)
        SQLINSTANCE = str(LogDB.find('InstanceName').text)
        SQLUSER = str(LogDB.find('Username').text)
        SQLDOMAIN = str(LogDB.find('Domain').text)
        SQLPASS = str(LogDB.find('Password').text)

    if SQLINSTANCE == 'None' or SQLINSTANCE == '':
        SQLSERVER == SQLSERVER
    else:
        SQLSERVER = SQLSERVER + '\\' + SQLINSTANCE
    if len(SQLDOMAIN) >= 1:
        SQLUSERNAME = SQLDOMAIN + '\\' + SQLUSER
    elif SQLDOMAIN == '' or SQLDOMAIN == 'None':
        print('SQL authentication will be used')
    else:
        print('Not a Triton Management Server, moving on')
if os.path.exists(EIPSET):
    # SQLPW = SQLPASS.split(':')
    # SQLPWD = SQLPW[2] + ' ' + SQLPW[0] + ' ' + SQLPW[1]
    # os.chdir(dsshome)
    # cmd = 'jre\\bin\\java -cp jre\\lib\\ext\\fortress.jar;tomcat\\lib\\tomcat-ext.jar com.pa.tomcat.resources.DecryptPassword' + ' ' + SQLPWD
    # CONVERTPW = os.popen(cmd).read()
    # FINAL = CONVERTPW.strip('\n')
    pass
else:
    print('Not a Triton Management Server, moving on')
enable_file_system_redirection().__enter__()
if os.path.exists(EIPSET) and SQLUSERNAME.find('None') >= 0:
    # conn = pyodbc.connect('DRIVER={SQL Server Native Client 11.0};SERVER=%s;DATABASE=wbsn-data-security;UID=%s;PWD=%s;' % (SQLSERVER, SQLUSER, FINAL))
    # cursor = conn.cursor()
    # DIR = '%s\\SVOS' % TMP
    # File = 'pa_config_props.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('SELECT * FROM PA_CONFIG_PROPERTIES')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'ws_sm_site_elements.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('SELECT * FROM WS_SM_SITE_ELEMENTS')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'LDAP_INFO.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('SELECT (select COUNT (*) from PA_REPO_GROUPS) + (select COUNT (*) from PA_REPO_USERS) + (select COUNT (*) from PA_REPO_COMPUTERS)')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('Number of objects: %s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'PA_EVENT_PARTITION_CATALOG.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('SELECT * from PA_EVENT_PARTITION_CATALOG')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'SyncedEPClients.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute("SELECT pds.ID, pds.UPDATE_DATE, pds.[key] as Hostname from PA_DYNAMIC_STATUS pds Left outer join PA_DYNAMIC_STATUS_PROPS pdsp ON pds.ID = pdsp.DYNAMIC_STATUS_ID where pdsp.STR_VALUE = 'endpoint_status_is_synced' and pdsp.INT_VALUE = '1'")
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'UnsyncCount.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute("SELECT COUNT(*) as UnsyncCount from PA_DYNAMIC_STATUS_PROPS where STR_VALUE = 'endpoint_status_is_synced' and INT_VALUE = '0'")
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'PA_EVENT_ARCHIVE_CONF.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('SELECT * from PA_EVENT_ARCHIVE_CONF')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'WS_ENDPNT_PROFILES.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('SELECT * from WS_ENDPNT_PROFILES')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'WS_ENDPNT_PROFILE_SERVERS.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('SELECT * from WS_ENDPNT_PROFILE_SERVERS')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'EP_Profiles_With_AP-DATA_Server.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute("select NAME from WS_ENDPNT_PROFILES where ID in (select EP_PROFILE_ID from WS_ENDPNT_PROFILE_SERVERS where EP_SERVER_ID in (select ID from WS_SM_SITE_ELEMENTS where DISCRIMINATOR = 'ENDPOINT_SRV' and HOSTNAME in (select HOSTNAME from WS_SM_SITE_ELEMENTS where DISCRIMINATOR = 'CNTNT_MNG_SRV')))")
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('AP-DATA Manager is part of the following EP Profiles.  If blank, it is not an EP Server: %s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'Audsyslogs.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('select ID, SEVERITY, STATUS, GENERATION_TIME_TS, SOURCE_NAME, SOURCE_SUB_TYPE, [MESSAGE] from PA_LOGGING select ID, GENERATION_TIME_TS, ADMIN_NAME, ROLE_NAME,[MESSAGE] from PA_AUDIT_INFO WHERE IS_LEADER_FOR_TX = 1')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'PARTITIONS.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('select PARTITION_INDEX, FROM_DATE, TO_DATE, STATUS from PA_EVENT_PARTITION_CATALOG')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'POLICIES.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute("select NAME, DEFINITION_TYPE from WS_PLC_POLICIES where IS_ENABLED = '1'")
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'CRAWLER_TASKS.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute('SELECT (select COUNT (*) from WS_PLC_CC_FILE_FINGERPRINTS) + (select COUNT (*) from WS_PLC_CC_DB_FINGERPRINTS) + (select COUNT (*) from WS_PLC_CC_MACHINE_LEARNING) + (select COUNT (*) from WS_PLC_DISCOVERY_TASKS)')
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # outfile.close
    # DIR = '%s\\SVOS' % TMP
    # File = 'UNHOOKED_APPS.csv'
    # FULL_PATH = os.path.join(DIR, File)
    # cursor.execute("select STR_VALUE from WS_ENDPNT_GLOB_CONFIG_PROPS where NAME = 'generalExcludedApplications'")
    # results = cursor.fetchall()
    # with open(FULL_PATH, 'wb') as outfile:
    #     for row in results:
    #         outfile.write('%s\n' % str(row))

    # cursor.close()
    # outfile.close
    pass
else:
    if os.path.exists(EIPSET) and SQLUSERNAME.find(SQLDOMAIN + '\\' + SQLUSER) >= 0:
        # handel = win32security.LogonUser(SQLUSER, SQLDOMAIN, FINAL, win32con.LOGON32_LOGON_INTERACTIVE, win32con.LOGON32_PROVIDER_DEFAULT)
        # win32security.ImpersonateLoggedOnUser(handel)
        # conn = pyodbc.connect('DRIVER={SQL Server};SERVER=%s;DATABASE=wbsn-data-security;UID=%s;PWD=%s;Trusted_Connection=yes' % (SQLSERVER, SQLUSERNAME, FINAL))
        # cursor = conn.cursor()
        # DIR = '%s\\SVOS' % TMP
        # File = 'pa_config_props.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT * FROM PA_CONFIG_PROPERTIES')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'SQL_VERSION_AND_EDITION.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT @@version')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'DB_SIZE.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute("SELECT DB_NAME(database_id) AS DatabaseName,Name AS Logical_Name,Physical_Name, (size*8)/1024 SizeMB FROM sys.master_files WHERE DB_NAME(database_id) = 'wbsn-data-security'")
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'ws_sm_site_elements.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT * FROM WS_SM_SITE_ELEMENTS')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'LDAP_INFO.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT (select COUNT (*) from PA_REPO_GROUPS) + (select COUNT (*) from PA_REPO_USERS) + (select COUNT (*) from PA_REPO_COMPUTERS)')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('Number of objects: %s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'PA_EVENT_PARTITION_CATALOG.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT * from PA_EVENT_PARTITION_CATALOG')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'SyncedEPClients.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute("SELECT pds.ID, pds.UPDATE_DATE, pds.[key] as Hostname from PA_DYNAMIC_STATUS pds Left outer join PA_DYNAMIC_STATUS_PROPS pdsp ON pds.ID = pdsp.DYNAMIC_STATUS_ID where pdsp.STR_VALUE = 'endpoint_status_is_synced' and pdsp.INT_VALUE = '1'")
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'UnsyncCount.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute("SELECT COUNT(*) as UnsyncCount from PA_DYNAMIC_STATUS_PROPS where STR_VALUE = 'endpoint_status_is_synced' and INT_VALUE = '0'")
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'PA_EVENT_ARCHIVE_CONF.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT * from PA_EVENT_ARCHIVE_CONF')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'WS_ENDPNT_PROFILES.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT * from WS_ENDPNT_PROFILES')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'WS_ENDPNT_PROFILE_SERVERS.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT * from WS_ENDPNT_PROFILE_SERVERS')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'EP_Profiles_With_AP-DATA_Server.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute("select NAME from WS_ENDPNT_PROFILES where ID in (select EP_PROFILE_ID from WS_ENDPNT_PROFILE_SERVERS where EP_SERVER_ID in (select ID from WS_SM_SITE_ELEMENTS where DISCRIMINATOR = 'ENDPOINT_SRV' and HOSTNAME in (select HOSTNAME from WS_SM_SITE_ELEMENTS where DISCRIMINATOR = 'CNTNT_MNG_SRV')))")
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('AP-DATA Manager is part of the following EP Profiles.  If blank, it is not an EP Server: %s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'Audsyslogs.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('select ID, SEVERITY, STATUS, GENERATION_TIME_TS, SOURCE_NAME, SOURCE_SUB_TYPE, [MESSAGE] from PA_LOGGING select ID, GENERATION_TIME_TS, ADMIN_NAME, ROLE_NAME,[MESSAGE] from PA_AUDIT_INFO WHERE IS_LEADER_FOR_TX = 1')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'PARTITIONS.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('select PARTITION_INDEX, FROM_DATE, TO_DATE, STATUS from PA_EVENT_PARTITION_CATALOG')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'POLICIES.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute("select NAME, DEFINITION_TYPE from WS_PLC_POLICIES where IS_ENABLED = '1'")
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'CRAWLER_TASKS.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute('SELECT (select COUNT (*) from WS_PLC_CC_FILE_FINGERPRINTS) + (select COUNT (*) from WS_PLC_CC_DB_FINGERPRINTS) + (select COUNT (*) from WS_PLC_CC_MACHINE_LEARNING) + (select COUNT (*) from WS_PLC_DISCOVERY_TASKS)')
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # outfile.close
        # DIR = '%s\\SVOS' % TMP
        # File = 'UNHOOKED_APPS.csv'
        # FULL_PATH = os.path.join(DIR, File)
        # cursor.execute("select STR_VALUE from WS_ENDPNT_GLOB_CONFIG_PROPS where NAME = 'generalExcludedApplications'")
        # results = cursor.fetchall()
        # with open(FULL_PATH, 'wb') as outfile:
        #     for row in results:
        #         outfile.write('%s\n' % str(row))

        # cursor.close()
        # outfile.close
        # win32security.RevertToSelf()
        # handel.close()
        pass
    else:
        print('Not a Triton Manager, or a legacy manager, moving on')
    print('Gathering OS info.  This may take a few minutes.  Please be patient.')
    msinfo = '%s\\System32\\msinfo32' % SYSROOT
    msinfoout = '%s\\SVOS\\SVOS.txt' % TMP
    subprocess.call([msinfo, '/report', msinfoout])
    for filename in os.listdir(CONF):
        with open(CONF + filename) as currentfile:
            text = currentfile.read()
            if 'DEBUG' in text or 'debug' in text:
                print(filename + ' ' + ' in debug mode')

    if os.path.isfile(CATPROP):
        print('The following are the cluster keys from Catalina.Properties, ca.cer, ep_cluster.key, and jetty.xml in that order')

        def catprop():
            searchfile = open(CATPROP, 'r')
            for line in searchfile:
                if 'wbsn' in line:
                    return line


        catdawg = catprop()
        cat = catdawg.replace('wbsn.com.pa.crypto.crypto.PAISCryptorV2.key=', '')
        cat1 = cat.split(':')
        cat2 = cat1[2] + ' ' + cat1[0] + ' ' + cat1[1]
        cat3 = cat2.replace('\n', ' ')
        os.chdir(dsshome)
        cmd2 = 'jre\\bin\\java -cp jre\\lib\\ext\\fortress.jar;tomcat\\lib\\tomcat-ext.jar com.pa.tomcat.resources.DecryptPassword' + ' ' + cat3
        CONVERTPW2 = os.popen(cmd2).read()
        print('catalina properties')
        print(CONVERTPW2)

        def ca():
            search = open(CACER, 'r')
            for line in search:
                if line.startswith('{4;'):
                    return line


        cacert = ca()
        ctool = 'cryptotool -k 4 -d -t' + ' ' + cacert
        CONVERT3 = os.popen(ctool).read()
        print('ca.cer')
        print(CONVERT3)
        os.chdir(KEYS)
        ctool2 = 'cryptotool -k 2 -g'
        CONVERT4 = os.popen(ctool2).read()
        print('epcluster.key')
        print(CONVERT4)
    else:
        print('Not a Triton Management Server, moving on')
    if os.path.isfile(JETTYXML):

        def jettyprop():
            searchfile = open(JETTYXML, 'r')
            for line in searchfile:
                if 'wsjf' in line:
                    return line


        jettydawg = jettyprop()
        j1 = re.sub('<[^>]*>', '', jettydawg)
        j2 = j1.replace('\n', '')
        j3 = j2.replace(' ', '')
        j4 = j3.split(':')
        j5 = j4[2] + ' ' + j4[0] + ' ' + j4[1]
        os.chdir(dsshome)
        jettycmd = 'jre\\bin\\java -cp jre\\lib\\ext\\fortress.jar;tomcat\\lib\\tomcat-ext.jar com.pa.tomcat.resources.DecryptPassword' + ' ' + j5
        CONVERTPW3 = os.popen(jettycmd).read()
        print('jetty.xml')
        print(CONVERTPW3)
    else:
        print('Not a Triton manager or version is below 8.1')
    DIR = '%s\\SVOS' % TMP
    File = 'DEP.txt'
    FULL_PATH = os.path.join(DIR, File)
    f = open(FULL_PATH, 'w')
    wm = '%s\\System32\\wbem\\WMIC.exe' % SYSROOT
    DEP = subprocess.call([wm, 'OS', 'Get', 'DataExecutionPrevention_SupportPolicy'], stdout=f)
    DEPSTR = str(DEP)
    f.close
    f = open(FULL_PATH, 'w')
    try:
        f.writelines('Data Execution Prevention Status:' + DEPSTR + '\n')
        f.writelines('0=Always Off, 1=Always On, 2=Opt In, 3=Opt out')
    finally:
        f.close

    if os.path.exists(EIPSET):
        tree = ET.parse(EIPSET)
        content = tree.getroot()
        for InstalledComponents in content.findall('InstalledComponents'):
            MANAGERS = str(InstalledComponents.find('Managers').text)

    else:
        print('Not a Triton Management Server, or a legacy manager. Moving on')
    jettyhome = os.getenv('JETTY_HOME', 'NONE')
    pythonpath = os.getenv('PYTHONPATH', 'NONE')
    activemqhome = os.getenv('ACTIVEMQ_HOME', 'NONE')
    javahome = os.getenv('JRE_HOME', 'NONE')
    DIR = '%s\\SVOS' % TMP
    File = 'System_Variables.txt'
    FULL_PATH = os.path.join(DIR, File)
    f = open(FULL_PATH, 'w')
    try:
        f.writelines('HOSTNAME:' + HOSTNAME + '\n')
        f.writelines('DSS_HOME:' + dsshome + '\n')
        f.writelines('PYTHONPATH:' + pythonpath + '\n')
        f.writelines('JETTY_HOME:' + jettyhome + '\n')
        f.writelines('JRE_HOME:' + javahome + '\n')
        f.writelines('ACTIVEMQ_HOME:' + activemqhome + '\n')
        if os.path.exists(EIPSET):
            f.writelines('SQL Server IP:' + SQLSERVER + '\n')
            f.writelines('Managers Installed: ' + MANAGERS + '\n')
    finally:
        f.close

    DIR = '%s\\SVOS' % TMP
    File = 'netstat.txt'
    FULL_PATH = os.path.join(DIR, File)
    f = open(FULL_PATH, 'w')
    ns = '%s\\System32\\NETSTAT' % SYSROOT
    NS = subprocess.call([ns, '-abno'], stdout=f)
    f.close
    DIR = '%s\\SVOS' % TMP
    File = 'sysinfo.txt'
    FULL_PATH = os.path.join(DIR, File)
    f = open(FULL_PATH, 'w')
    sinfo = '%s\\System32\\systeminfo' % SYSROOT
    SYSINFO = subprocess.call([sinfo], stdout=f)
    f.close
    DIR = '%s\\SVOS' % TMP
    File = 'service_info.txt'
    FULL_PATH = os.path.join(DIR, File)
    f = open(FULL_PATH, 'w')
    serco = '%s\\System32\\sc' % SYSROOT
    dssservice = subprocess.call([serco, 'qc', 'DSSMANAGER', '5000'], stdout=f)
    eipservice = subprocess.call([serco, 'qc', 'EIPMANAGER', '5000'], stdout=f)
    sqlservice = subprocess.call([serco, 'qc', 'MSSQLSERVER', '5000'], stdout=f)
    fpdbservice = subprocess.call([serco, 'qc', 'PAFPREP', '5000'], stdout=f)
    policyengineservice = subprocess.call([serco, 'qc', 'POLICYENGINE', '5000'], stdout=f)
    batchserverservice = subprocess.call([serco, 'qc', 'DSSBATCHSERVER', '5000'], stdout=f)
    messagebrokerservice = subprocess.call([serco, 'qc', 'DSSMESSAGEBROKER', '5000'], stdout=f)
    epserverservice = subprocess.call([serco, 'qc', 'EPSERVER', '5000'], stdout=f)
    workschedservice = subprocess.call([serco, 'qc', 'WORKSCHEDULER', '5000'], stdout=f)
    mgmtdservice = subprocess.call([serco, 'qc', 'MGMTD', '5000'], stdout=f)
    pgsqlservice = subprocess.call([serco, 'qc', 'PGSQLEIP', '5000'], stdout=f)
    eipproxyservice = subprocess.call([serco, 'qc', 'EIPMANAGERPROXY', '5000'], stdout=f)
    f.close
    DIR = '%s\\SVOS' % TMP
    File = 'memory_cpu_hdd.txt'
    FULL_PATH = os.path.join(DIR, File)
    f = open(FULL_PATH, 'w')
    SYSINFO = subprocess.call([wm, 'computersystem', 'Get', 'TotalPhysicalMemory', '/Value'], stdout=f)
    SYSINFO = subprocess.call([wm, 'cpu', 'Get', 'Name,', 'NumberOfCores,', 'NumberOfLogicalProcessors'], stdout=f)
    SYSINFO = subprocess.call([wm, 'logicaldisk', 'Get', 'Name,', 'Size,', 'Freespace'], stdout=f)
    f.close
    time.sleep(5)
    for line in open('%s\\SVOS\\memory_cpu_hdd.txt' % TMP, 'r'):
        if 'TotalPhysicalMemory' in line:
            print(line)

    for line in open('%s\\SVOS\\memory_cpu_hdd.txt' % TMP, 'r'):
        if 'TotalPhysicalMemory' in line:
            print(re.findall('\\d+', line))

    DIR = '%s\\SVOS' % TMP
    File = 'RunningAntiVirus.txt'
    FULL_PATH = os.path.join(DIR, File)
    f = open(FULL_PATH, 'w')
    command = 'wmic process get description | findstr -i "avgrsx avastsvc afwserv vsserv clamd nod32 fspex kavsvc mcshield pavsrv smc tmproxy"'
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    while True:
        line = p.stdout.readline()
        if line:
            f.write(line)
        else:
            break

    DIR = '%s\\SVOS' % TMP
    File = 'GPO_Info.txt'
    FULL_PATH = os.path.join(DIR, File)
    f = open(FULL_PATH, 'w')
    gpresult = '%s\\System32\\gpresult' % SYSROOT
    SYSINFO = subprocess.call([gpresult, '/r'], stdout=f)
    f.close
    print('Thank you for running SVOS.  When the command prompt returns, the archive process will be complete and the generated file can be found in ' + userprofile + '\\Desktop\\.  Please send this to your Forcepoint Representative for review.')

    def getDSversion():
        areg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        akey = OpenKey(areg, 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Data Security')
        result = QueryValueEx(akey, 'DisplayVersion')
        return result[0]


    print('AP-DATA verion')
    print(getDSversion())

    def getrepolocation():
        areg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        akey = OpenKey(areg, 'SOFTWARE\\Wow6432Node\\Websense\\Data Security')
        result = QueryValueEx(akey, 'RepositoryDir')
        return result[0]


    print('Forensics Repository location')
    print(getrepolocation())

    def main():
        zipper('%s\\SVOS' % TMP, '%s\\FP.zip' % TMP)


    def zipper(dir, zip_file):
        zip = zipfile.ZipFile(zip_file, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=True)
        root_len = len(os.path.abspath(dir))
        for root, dirs, files in os.walk(dir):
            archive_root = os.path.abspath(root)[root_len:]
            for f in files:
                fullpath = os.path.join(root, f)
                archive_name = os.path.join(archive_root, f)
                zip.write(fullpath, archive_name, zipfile.ZIP_DEFLATED)

        zip.close()
        return zip_file


    if __name__ == '__main__':
        main()
shutil.move('%s\\FP.zip' % TMP, FPARCHIVE)