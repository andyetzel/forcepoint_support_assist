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
import ctypes
import zipfile
import win32security
import win32con
import xml.etree.ElementTree as ET
import logging
import win32com.client
import re
import time
import platform
import getpass
import win32api
from distutils.dir_util import copy_tree

try:
    import json
except ImportError:
    import simplejson as json 


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


def get_eip_path():
    try:
        py_version = platform.python_version()
        major, minor, patch = [int(x, 10) for x in py_version.split('.')]
        if major == 3:
            import winreg
            #from winreg import *
            try:
                hKey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'Software\\Wow6432Node\\Websense\\EIP Infra')
                result = winreg.QueryValueEx(hKey, 'INSTALLDIR')
                return result[0]
            except OSError:
                exists = False
            try:
                hKey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'Software\\Wow6432Node\\Websense\\EIP Infra')
            except OSError:
                print('Not a Triton Management Server')
        elif major == 2:
            import _winreg
            #from _winreg import *
            try:
                hKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, 'Software\\Wow6432Node\\Websense\\EIP Infra')
                result = _winreg.QueryValueEx(hKey, 'INSTALLDIR')
                return result[0]
            except OSError:
                exists = False
            try:
                hKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, 'Software\\Wow6432Node\\Websense\\EIP Infra')
            except OSError:
                print('Not a Triton Management Server')
    except NotImplementedError:
        print('Unknown version of Python')

def getDSversion():
    try:
        py_version = platform.python_version()
        major, minor, patch = [int(x, 10) for x in py_version.split('.')]
    except NotImplementedError:
        print('Unknown version of Python')
    try:
        if major == 3:
            import winreg
            #from winreg import *
            try:
                areg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                akey = winreg.OpenKey(areg, 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Data Security')
                result = winreg.QueryValueEx(akey, 'DisplayVersion')
                return result[0]
            except NotImplementedError:
                print('Not a AP-DATA Server')
        elif major == 2:
            import _winreg
            try:
                areg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
                akey = _winreg.OpenKey(areg, 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Data Security')
                result = _winreg.QueryValueEx(akey, 'DisplayVersion')
                return result[0]
            except NotImplementedError:
                print('Not a AP-DATA Server')
    except NotImplementedError:
        print('Not a AP-DATA Server')

def fingerprint_repository_location():
    try:
        py_version = platform.python_version()
        major, minor, patch = [int(x, 10) for x in py_version.split('.')]
        if major == 3:
            import winreg
            #from winreg import *
            try:
                areg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                akey = winreg.OpenKey(areg, 'SOFTWARE\\Wow6432Node\\Websense\\Data Security')
                result = winreg.QueryValueEx(akey, 'RepositoryDir')
                return result[0]
            except NotImplementedError:
                print('Not a AP-DATA Server')
        elif major == 2:
            import _winreg
            try:
                areg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
                akey = _winreg.OpenKey(areg, 'SOFTWARE\\Wow6432Node\\Websense\\Data Security')
                result = _winreg.QueryValueEx(akey, 'RepositoryDir')
                return result[0]
            except NotImplementedError:
                print('Not a AP-DATA Server')
    except NotImplementedError:
        print('Unknown version of Python')


TMP_DIR = os.getenv('TMP', 'NONE')
SVOS_DIR = '%s\\SVOS\\' % TMP_DIR
SYS_ROOT = os.getenv('SystemRoot', 'NONE')
USER_PROFILE_DIR = os.getenv('USERPROFILE', 'NONE')
EIP_DIR = get_eip_path()
DSS_DIR = os.getenv('DSS_HOME', 'NONE')
JETTY_DIR = os.getenv('JETTY_HOME', 'NONE') #jettyhome
PYTHON_DIR = os.getenv('PYTHONPATH', 'NONE') #pythonpath
AMQ_DIR = os.getenv('ACTIVEMQ_HOME', 'NONE') #activemqhome
JRE_DIR = os.getenv('JRE_HOME', 'NONE') #javahome
HOST_NAME = socket.gethostname() #HOSTNAME
FPARCHIVE = datetime.now().strftime(USER_PROFILE_DIR + '\\Desktop\\FPAssist_' + '_' + HOST_NAME + '_%Y%m%d-%H%M%S.zip')
DEBUG_LOG = os.path.join(SVOS_DIR, 'forcepoint_support_assist.log')

# Create SVOS directory in temp, delete old if exists
if os.path.exists(SVOS_DIR):
    shutil.rmtree(SVOS_DIR)
    os.mkdir(SVOS_DIR)
else:
    os.mkdir(SVOS_DIR)

class Logger(object):
    def __init__(self, filename='Default.log'):
        self.terminal = sys.stdout
        self.log = open(filename, 'a')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

sys.stdout = Logger(DEBUG_LOG)

print('Forcepoint Support Assist v0.3.0')

if DSS_DIR == 'NONE':
    servicemanager.LogInfoMsg('This system  is not a Forcepoint DLP Server.  The Forcepoint Support Assist script will exit now.')
    sys.exit()

collect_me = '''
{
  "EIP": [
    {"source": "/EIPSettings.xml", "destination": "/EIP/"},
    {"source": "/apache/logs/", "destination": "/EIP/apache/"},
    {"source": "/tomcat/logs/", "destination": "/EIP/tomcat/"},
    {"source": "/logs/", "destination": "/EIP/logs/"}
  ],
  "DSS": [
    {"source": "/Logs/", "destination": "/DSS/Logs"},
    {"source": "/ResourceResolver/ResourceResolverServerMaster.db", "destination": "/DSS/ResourceResolver/"},
    {"source": "/tomcat/conf/Catalina/localhost/dlp.xml", "destination": "/DSS/tomcat/"},
    {"source": "/tomcat/conf/catalina.properties", "destination": "/DSS/tomcat/"},
    {"source": "/tomcat/logs/", "destination": "/DSS/tomcat/"},
    {"source": "/apache/conf/httpd.conf", "destination": "/DSS/apache/"},
    {"source": "/apache/conf/extra/httpd-ssl.conf", "destination": "/DSS/apache/"},
    {"source": "/apache/logs/", "destination": "/DSS/apache/"},
    {"source": "/keys/ep_cluster.key", "destination": "/DSS/keys/"},
    {"source": "/keys/machine.key", "destination": "/DSS/keys/"},
    {"source": "/ConfigurationStore/", "destination": "/DSS/ConfigurationStore/"},
    {"source": "/Data-Batch-Server/service-container/container/logs/service_logs/", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "/Data-Batch-Server/service-container/container/logs/", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "/Data-Batch-Server//service-container/container/etc/jetty.xml", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "EndPointServer.config.xml", "destination": "/DSS/"},
    {"source": "/ca.cer", "destination": "/DSS/"},
    {"source": "/conf/", "destination": "/DSS/conf/"},
    {"source": "/extractor.config.xml", "destination": "/DSS/"},
    {"source": "/mediator/logs/mediator.out", "destination": "/DSS/mediator/"},
    {"source": "/Data-Batch-Server/logs/", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "/MessageBroker/data/activemq.log", "destination": "/DSS/MessageBroker/"},
    {"source": "/MessageBroker/data/audit.log", "destination": "/DSS/MessageBroker/"},
    {"source": "/MessageBroker/data/service_logs/", "destination": "/DSS/MessageBroker/"},
    {"source": "/OCRServer.config.xml", "destination": "/DSS/"},
    {"source": "/FileEncryptor.log", "destination": "/DSS/"},
    {"source": "/PolicyEngine.policy.xml", "destination": "/DSS/"},
    {"source": "/PolicyEngine.policy.xml.bak", "destination": "/DSS/"},
    {"source": "/allcerts.cer", "destination": "/DSS/"},
    {"source": "/HostCert.key", "destination": "/DSS/"},
    {"source": "/Data-Batch-Server/service-container/container/webapps/data-batch-services.xml", "destination": "/DSS/Data-Batch-Server/"}
  ],
  "WINDOWS": [
    {"source": "C:/Windows/System32/winevt/Logs/Application.evtx", "destination": "/Windows/"},
    {"source": "C:/Windows/System32/winevt/Logs/System.evtx", "destination": "/Windows/"}
  ]
}
'''

# print('Fingerprint Repository location')
# print(fingerprint_repository_location())

def copy_data(src,dst):
    try:
        if os.path.isdir(src):
            try:
                # shutil.copytree(src, dst, dirs_exist_ok=True)
                # print('Copied directory ' + src)
                copy_tree(src, dst, preserve_times=1)
                print('Directory: ' + src)
            except OSError: # python >2.5
                print('WARN: Unable to copy directory. Skipping...')
        if os.path.isfile(src):
            try:
                shutil.copy2(src, dst)
                print('File: ' + src)
            except:
                print('WARN: Unable to copy file ' + src + '. Skipping...')
    except IOError:
        raise IOError('ERROR: An unexpected error has occurred while copying from ' + src + ' to ' + dst + '. Please contact Forcepoint Technical Support for further assistance.')

def detect_json_config():
    #Look for custom JSON settings
    if os.path.isfile('custom.json'):
         print('Using custom JSON configuration.')
         custom_file = 'custom.json'
         with open(custom_file) as f:
            return json.loads(f.read())
    else:
         print('Using default JSON configuration.')
         return json.loads(collect_me)
         
def parse_json_config():
    data_set = detect_json_config()
    for category in data_set:
        if category == "EIP":
            print('\n===== Copying EIP logs =====')
            for item in data_set[category]:
                dst_path = SVOS_DIR + item['destination']
                if not os.path.exists(dst_path):
                    os.makedirs(dst_path)
                src_path = EIP_DIR + item['source']
                copy_data(src_path,dst_path)
        if category == "DSS":
            print('\n===== Copying DSS logs =====')
            for item in data_set[category]:
                dst_path = SVOS_DIR + item['destination']
                if not os.path.exists(dst_path):
                    os.makedirs(dst_path)
                src_path = DSS_DIR + item['source']
                copy_data(src_path,dst_path)
        if category == "WINDOWS":
            print('\n===== Copying Windows Event logs =====')
            for item in data_set[category]:
                dst_path = SVOS_DIR + item['destination']
                if not os.path.exists(dst_path):
                    os.makedirs(dst_path)
                src_path = item['source']
                copy_data(src_path,dst_path)


print('AP-DATA verion')
print(getDSversion())

#Start log collection
parse_json_config()

EIP_XML = EIP_DIR + "/EIPSettings.xml"
if os.path.exists(EIP_XML):
    print('Found EIPSettings.xml')
    try:
        tree = ET.parse(EIP_XML)
        content = tree.getroot()
        for LogDB in content.findall('LogDB'):
            SQLSERVER = str(LogDB.find('Host').text)
            SQLPORT = str(LogDB.find('Port').text)
            SQLINSTANCE = str(LogDB.find('InstanceName').text.rstrip())
            #SQLUSER = str(LogDB.find('Username').text)
            #SQLDOMAIN = str(LogDB.find('Domain').text)
            #SQLPASS = str(LogDB.find('Password').text)
        if SQLINSTANCE == 'None' or SQLINSTANCE == '':
            SQLSERVER == SQLSERVER
        else:
            SQLSERVER = SQLSERVER + '\\' + SQLINSTANCE
        print('SQLSERVER is: ' + SQLSERVER)
        print('SQLINSTANCE is: "' + SQLINSTANCE + '"')
        print('SQLPORT is: ' + SQLPORT)
    except OSError:
        print('ERROR: Unable to read EIPSettings.xml')
else:
    print('ERROR: Unable to locate EIPSettings.xml')

def log_system_details():
    FULL_PATH = os.path.join(SVOS_DIR, 'System_Variables.txt')
    f = open(FULL_PATH, 'w')
    try:
        f.writelines('HOSTNAME:' + HOST_NAME + '\n')
        f.writelines('DSS_HOME:' + DSS_DIR + '\n')
        f.writelines('PYTHONPATH:' + PYTHON_DIR + '\n')
        f.writelines('JETTY_HOME:' + JETTY_DIR + '\n')
        f.writelines('JRE_HOME:' + JRE_DIR + '\n')
        f.writelines('ACTIVEMQ_HOME:' + AMQ_DIR + '\n')
        if EIP_DIR != 'NONE':
            f.writelines('SQL Server IP:' + SQLSERVER + '\n')
            f.writelines('Managers Installed: ' + MANAGERS + '\n')
    finally:
        f.close

def run_sql_scripts(db_cursor):
    sql_script_params = [
        {"pa_config_props.csv": "SELECT * FROM PA_CONFIG_PROPERTIES"},
        {"SQL_VERSION_AND_EDITION.csv": "SELECT @@version"},
        {"DB_SIZE.csv": "SELECT DB_NAME(database_id) AS DatabaseName,Name AS Logical_Name,Physical_Name, (size*8)/1024 SizeMB FROM sys.master_files WHERE DB_NAME(database_id) = 'wbsn-data-security'"},
        {"ws_sm_site_elements.csv": "SELECT * FROM WS_SM_SITE_ELEMENTS"},
        {"LDAP_INFO.csv": "SELECT (select COUNT (*) from PA_REPO_GROUPS) + (select COUNT (*) from PA_REPO_USERS) + (select COUNT (*) from PA_REPO_COMPUTERS)"},
        {"PA_EVENT_PARTITION_CATALOG.csv": "SELECT * from PA_EVENT_PARTITION_CATALOG"},
        {"SyncedEPClients.csv": "SELECT pds.ID, pds.UPDATE_DATE, pds.[key] as Hostname from PA_DYNAMIC_STATUS pds Left outer join PA_DYNAMIC_STATUS_PROPS pdsp ON pds.ID = pdsp.DYNAMIC_STATUS_ID where pdsp.STR_VALUE = 'endpoint_status_is_synced' and pdsp.INT_VALUE = '1'"},
        {"UnsyncCount.csv": "SELECT COUNT(*) as UnsyncCount from PA_DYNAMIC_STATUS_PROPS where STR_VALUE = 'endpoint_status_is_synced' and INT_VALUE = '0'"},
        {"PA_EVENT_ARCHIVE_CONF.csv": "SELECT * from PA_EVENT_ARCHIVE_CONF"},
        {"WS_ENDPNT_PROFILES.csv": "SELECT * from WS_ENDPNT_PROFILES"},
        {"WS_ENDPNT_PROFILE_SERVERS.csv": "SELECT * from WS_ENDPNT_PROFILE_SERVERS"},
        {"EP_Profiles_With_AP-DATA_Server.csv": "select NAME from WS_ENDPNT_PROFILES where ID in (select EP_PROFILE_ID from WS_ENDPNT_PROFILE_SERVERS where EP_SERVER_ID in (select ID from WS_SM_SITE_ELEMENTS where DISCRIMINATOR = 'ENDPOINT_SRV' and HOSTNAME in (select HOSTNAME from WS_SM_SITE_ELEMENTS where DISCRIMINATOR = 'CNTNT_MNG_SRV')))"},
        {"Audsyslogs.csv": "select ID, SEVERITY, STATUS, GENERATION_TIME_TS, SOURCE_NAME, SOURCE_SUB_TYPE, [MESSAGE] from PA_LOGGING select ID, GENERATION_TIME_TS, ADMIN_NAME, ROLE_NAME,[MESSAGE] from PA_AUDIT_INFO WHERE IS_LEADER_FOR_TX = 1"},
        {"PARTITIONS.csv": "select PARTITION_INDEX, FROM_DATE, TO_DATE, STATUS from PA_EVENT_PARTITION_CATALOG"},
        {"POLICIES.csv": "select NAME, DEFINITION_TYPE from WS_PLC_POLICIES where IS_ENABLED = '1'"},
        {"CRAWLER_TASKS.csv": "SELECT (select COUNT (*) from WS_PLC_CC_FILE_FINGERPRINTS) + (select COUNT (*) from WS_PLC_CC_DB_FINGERPRINTS) + (select COUNT (*) from WS_PLC_CC_MACHINE_LEARNING) + (select COUNT (*) from WS_PLC_DISCOVERY_TASKS)"},
        {"UNHOOKED_APPS.csv": "select STR_VALUE from WS_ENDPNT_GLOB_CONFIG_PROPS where NAME = 'generalExcludedApplications'"}
    ]
    DIR = '%s\\SVOS' % TMP_DIR
    print('Running SQL scripts...')
    try:
        for param in sql_script_params:
            for file_name, query_string in param.items():
                file_path = os.path.join(DIR, file_name)
                db_cursor.execute(query_string)
                query_results = db_cursor.fetchall()
                with open(file_path, 'wb') as output_file:
                    for row in query_results:
                        output_file.write('%s\n' % str(row))
                output_file.close
    except IOError:
        print('ERROR: Unable to run SQL scripts.')

try:
    print('Connecting to database using Windows Authentication for current user "' + win32api.GetUserName() + '"')
    conn = pyodbc.connect(r'DRIVER={SQL Server};Server=%s;Database=wbsn-data-security;Trusted_Connection=yes;' % (SQLSERVER))
    cursor = conn.cursor()
    print('Connected to database.')
    windows_auth = True
    run_sql_scripts(cursor)
except:
    print('ERROR: Could not establish connection to database via Windows Authentication for current user "' + win32api.GetUserName() + '"')
    windows_auth = False

if windows_auth == False:
    try:
        print('Trying SQL Authentication. Please enter valid SQL database credentials.')
        try:
            py_version = platform.python_version()
            major, minor, patch = [int(x, 10) for x in py_version.split('.')]
            if major == 3:
                #python 3.x implementation
                user = input('Username: ')
            elif major == 2:
                #python 2.x implementation
                user = raw_input('Username: ')
        except NotImplementedError:
            print('Unknown version of Python')
        passwd = getpass.getpass('Password: ')
        conn = pyodbc.connect('DRIVER={SQL Server Native Client 11.0};SERVER=%s;DATABASE=wbsn-data-security;UID=%s;PWD=%s;' % (SQLSERVER, user, passwd))
        cursor = conn.cursor()
        print('Connected to database.')
        run_sql_scripts(cursor)
        conn.close()
    except IOError:
        print('ERROR: Could not establish connection to database via SQL Authentication for user "' + user + '"')

enable_file_system_redirection().__enter__()

print('Gathering OS info.  This may take a few minutes.  Please be patient.')
msinfo = '%s\\System32\\msinfo32' % SYS_ROOT
msinfoout = '%s\\SVOS\\SVOS.txt' % TMP_DIR
subprocess.call([msinfo, '/report', msinfoout])

def check_dlp_debugging():
    DSS_CONF = DSS_DIR + '/conf'
    for filename in os.listdir(DSS_CONF):
        with open(DSS_CONF + filename) as currentfile:
            text = currentfile.read()
            if 'DEBUG' in text or 'debug' in text:
                print(filename + ' ' + ' in debug mode')


CATPROP = '%s\\tomcat\\conf\\catalina.properties' % DSS_DIR
if os.path.isfile(CATPROP):
    print('The following are the cluster keys from Catalina.Properties: ca.cer, ep_cluster.key, and jetty.xml, in that order')
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
    os.chdir(DSS_DIR)
    cmd2 = 'jre\\bin\\java -cp jre\\lib\\ext\\fortress.jar;tomcat\\lib\\tomcat-ext.jar com.pa.tomcat.resources.DecryptPassword' + ' ' + cat3
    CONVERTPW2 = os.popen(cmd2).read()
    print('catalina properties')
    print(CONVERTPW2)
    def ca():
        CACER = '%s\\ca.cer' % DSS_DIR
        search = open(CACER, 'r')
        for line in search:
            if line.startswith('{4;'):
                return line
    cacert = ca()
    ctool = 'cryptotool -k 4 -d -t' + ' ' + cacert
    CONVERT3 = os.popen(ctool).read()
    print('ca.cer')
    print(CONVERT3)
    KEYS = '%s\\keys\\' % DSS_DIR
    os.chdir(KEYS)
    ctool2 = 'cryptotool -k 2 -g'
    CONVERT4 = os.popen(ctool2).read()
    print('epcluster.key')
    print(CONVERT4)
else:
    print('Not a Triton Management Server, moving on')


JETTYXML = '%s\\service-container\\container\\etc\\jetty.xml' % JETTY_DIR
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
    os.chdir(DSS_DIR)
    jettycmd = 'jre\\bin\\java -cp jre\\lib\\ext\\fortress.jar;tomcat\\lib\\tomcat-ext.jar com.pa.tomcat.resources.DecryptPassword' + ' ' + j5
    CONVERTPW3 = os.popen(jettycmd).read()
    print('jetty.xml')
    print(CONVERTPW3)
else:
    print('Not a Triton manager or version is below 8.1')


DIR = '%s\\SVOS' % TMP_DIR
File = 'DEP.txt'
FULL_PATH = os.path.join(DIR, File)
f = open(FULL_PATH, 'w')
wm = '%s\\System32\\wbem\\WMIC.exe' % SYS_ROOT
DEP = subprocess.call([wm, 'OS', 'Get', 'DataExecutionPrevention_SupportPolicy'], stdout=f)
DEPSTR = str(DEP)
f.close
f = open(FULL_PATH, 'w')
try:
    f.writelines('Data Execution Prevention Status:' + DEPSTR + '\n')
    f.writelines('0=Always Off, 1=Always On, 2=Opt In, 3=Opt out')
finally:
    f.close


if os.path.exists(EIP_XML):
    tree = ET.parse(EIP_XML)
    content = tree.getroot()
    for InstalledComponents in content.findall('InstalledComponents'):
        MANAGERS = str(InstalledComponents.find('Managers').text)
else:
    print('Not a Triton Management Server, or a legacy manager. Moving on')


DIR = '%s\\SVOS' % TMP_DIR
File = 'netstat.txt'
FULL_PATH = os.path.join(DIR, File)
f = open(FULL_PATH, 'w')
ns = '%s\\System32\\NETSTAT' % SYS_ROOT
NS = subprocess.call([ns, '-abno'], stdout=f)
f.close
DIR = '%s\\SVOS' % TMP_DIR
File = 'sysinfo.txt'
FULL_PATH = os.path.join(DIR, File)
f = open(FULL_PATH, 'w')
sinfo = '%s\\System32\\systeminfo' % SYS_ROOT
SYSINFO = subprocess.call([sinfo], stdout=f)
f.close
DIR = '%s\\SVOS' % TMP_DIR
File = 'service_info.txt'
FULL_PATH = os.path.join(DIR, File)
f = open(FULL_PATH, 'w')
serco = '%s\\System32\\sc' % SYS_ROOT
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
DIR = '%s\\SVOS' % TMP_DIR
File = 'memory_cpu_hdd.txt'
FULL_PATH = os.path.join(DIR, File)
f = open(FULL_PATH, 'w')
SYSINFO = subprocess.call([wm, 'computersystem', 'Get', 'TotalPhysicalMemory', '/Value'], stdout=f)
SYSINFO = subprocess.call([wm, 'cpu', 'Get', 'Name,', 'NumberOfCores,', 'NumberOfLogicalProcessors'], stdout=f)
SYSINFO = subprocess.call([wm, 'logicaldisk', 'Get', 'Name,', 'Size,', 'Freespace'], stdout=f)
f.close
time.sleep(5)


for line in open('%s\\SVOS\\memory_cpu_hdd.txt' % TMP_DIR, 'r'):
    if 'TotalPhysicalMemory' in line:
        print(line)


for line in open('%s\\SVOS\\memory_cpu_hdd.txt' % TMP_DIR, 'r'):
    if 'TotalPhysicalMemory' in line:
        print(re.findall('\\d+', line))


DIR = '%s\\SVOS' % TMP_DIR
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


DIR = '%s\\SVOS' % TMP_DIR
File = 'GPO_Info.txt'
FULL_PATH = os.path.join(DIR, File)
f = open(FULL_PATH, 'w')
gpresult = '%s\\System32\\gpresult' % SYS_ROOT
SYSINFO = subprocess.call([gpresult, '/r'], stdout=f)
f.close
print('Thank you for running Forcepoint Support Assist.  \nA zip file can be found here: ' + USER_PROFILE_DIR + '\\Desktop\\.  \nPlease send this file to Forcepoint Support for review.')


def main():
    zipper('%s\\SVOS' % TMP_DIR, '%s\\FP.zip' % TMP_DIR)


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
shutil.move('%s\\FP.zip' % TMP_DIR, FPARCHIVE)