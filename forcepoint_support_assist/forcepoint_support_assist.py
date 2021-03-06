from __future__ import with_statement
import os
import socket
import sys
from datetime import datetime
import subprocess
from subprocess import Popen, PIPE, STDOUT
import shutil
import stat
import pyodbc
import ctypes
import zipfile
import xml.etree.ElementTree as ET
import logging
import re
import getpass
import win32api
from distutils.dir_util import copy_tree

# Provides compatability between Python 2 and Python 3
try:
    import json
except ImportError:
    import simplejson as json


# Provides compatability between Python 2 and Python 3
try:
    import winreg
except ImportError:
    import _winreg as winreg


# Required if using 32-bit Python on a 64-bit Windows system.
class disable_file_system_redirection:
    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection

    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)


# Required if using 32-bit Python on a 64-bit Windows system.
class enable_file_system_redirection:
    _enable = ctypes.windll.kernel32.Wow64EnableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection

    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._enable(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)


def onerror(func, path, exc_info):
    """
    Error handler for ``shutil.rmtree``.

    If the error is due to an access error (read only file)
    it attempts to add write permission and then retries.

    If the error is for another reason it re-raises the error.

    Usage : ``shutil.rmtree(path, onerror=onerror)``
    """
    if not os.access(path, os.W_OK):
        # Is the error an access error ?
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise OSError


# GLOBAL CONSTANTS
TMP_DIR = os.getenv('TMP', 'NONE')
FPASSIST_DIR = '%s\\FPASSIST\\' % TMP_DIR
SYS_ROOT = os.getenv('SystemRoot', 'NONE')
USER_PROFILE_DIR = os.getenv('USERPROFILE', 'NONE')
DSS_DIR = os.getenv('DSS_HOME', 'NONE')
JETTY_DIR = os.getenv('JETTY_HOME', 'NONE')  # jettyhome
PYTHON_DIR = os.getenv('PYTHONPATH', 'NONE')  # pythonpath
AMQ_DIR = os.getenv('ACTIVEMQ_HOME', 'NONE')  # activemqhome
JRE_DIR = os.getenv('JRE_HOME', 'NONE')  # javahome
HOST_NAME = socket.gethostname()  # HOSTNAME
FP_ARCH_PTH = USER_PROFILE_DIR + '\\Desktop\\FPAssist_' + HOST_NAME
FPARCHIVE = datetime.now().strftime(FP_ARCH_PTH + '_%Y%m%d-%H%M%S.zip')
DEBUG_LOG = os.path.join(FPASSIST_DIR, 'FPassist.log')
CATPROP = '%s\\tomcat\\conf\\catalina.properties' % DSS_DIR
KEYS = '%s\\keys\\' % DSS_DIR
JETTYXML = '%s\\service-container\\container\\etc\\jetty.xml' % JETTY_DIR

# The pre-defined data set to be collected
# Override with a custom.json file located in the same path
collect_me = '''
{
  "EIP": [
    {"source": "/EIPSettings.xml", "destination": "/EIP/"},
    {"source": "/EIPBackup.xml", "destination": "/EIP/"},
    {"source": "/ca.cer", "destination": "/EIP/"},
    {"source": "/apache/logs/", "destination": "/EIP/apache/"},
    {"source": "/apache/conf/", "destination": "/EIP/apache/"},
    {"source": "/tomcat/logs/", "destination": "/EIP/tomcat/"},
    {"source": "/tomcat/conf/", "destination": "/EIP/tomcat/"},
    {"source": "/logs/", "destination": "/EIP/logs/"}
  ],
  "DSS": [
    {"source": "/apache/logs/", "destination": "/DSS/apache/logs/"},
    {"source": "/apache/conf/httpd.conf", "destination": "/DSS/apache/"},
    {"source": "/apache/conf/extra/httpd-ssl.conf", "destination": "/DSS/apache/"},
    {"source": "/conf/", "destination": "/DSS/conf/"},
    {"source": "/ConfigurationStore/", "destination": "/DSS/ConfigurationStore/"},
    {"source": "/Data-Batch-Server/logs/", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "/Data-Batch-Server/service-container/container/logs/", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "/Data-Batch-Server//service-container/container/etc/jetty.xml", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "/Data-Batch-Server/service-container/container/logs/service_logs/", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "/Data-Batch-Server/service-container/container/webapps/data-batch-services.xml", "destination": "/DSS/Data-Batch-Server/"},
    {"source": "/DiscoveryJobs/", "destination": "/DSS/DiscoveryJobs/"},
    {"source": "/EPS_CAMEL/data/service_logs/", "destination": "/DSS/EPS_CAMEL/"},
    {"source": "/EPS_CAMEL/keystore/", "destination": "/DSS/EPS_CAMEL/"},
    {"source": "/EPS_CAMEL/service-config/logs/", "destination": "/DSS/EPS_CAMEL/"},
    {"source": "/EPS_CAMEL/service-config/application.properties", "destination": "/DSS/EPS_CAMEL/"},
    {"source": "/EPS_CAMEL/service-config/camel.log", "destination": "/DSS/EPS_CAMEL/"},
    {"source": "/EPS_CAMEL/service-config/log4j2.xml", "destination": "/DSS/EPS_CAMEL/"},
    {"source": "/ResourceResolver/ResourceResolverServerMaster.db", "destination": "/DSS/ResourceResolver/"},
    {"source": "/ResourceResolver/RRUserDefinedResourceMasterRiskLevel.xml", "destination": "/DSS/ResourceResolver/"},
    {"source": "/ResourceResolver/RRUserDefinedResourceMaster.xml", "destination": "/DSS/ResourceResolver/"},
    {"source": "/tomcat/logs/", "destination": "/DSS/tomcat/"},
    {"source": "/tomcat/conf/catalina.properties", "destination": "/DSS/tomcat/"},
    {"source": "/tomcat/conf/Catalina/localhost/dlp.xml", "destination": "/DSS/tomcat/"},
    {"source": "/keys/", "destination": "/DSS/keys/"},
    {"source": "/Logs/", "destination": "/DSS/Logs"},
    {"source": "/mediator/logs/mediator.out", "destination": "/DSS/mediator/"},
    {"source": "/MessageBroker/data/activemq.log", "destination": "/DSS/MessageBroker/"},
    {"source": "/MessageBroker/data/audit.log", "destination": "/DSS/MessageBroker/"},
    {"source": "/MessageBroker/data/service_logs/", "destination": "/DSS/MessageBroker/"},
    {"source": "/allcerts.cer", "destination": "/DSS/"},
    {"source": "/ca.cer", "destination": "/DSS/"},
    {"source": "/DistList.csv", "destination": "/DSS/"},
    {"source": "/host.cer", "destination": "/DSS/"},
    {"source": "/host.key", "destination": "/DSS/"},
    {"source": "/HostCert.key", "destination": "/DSS/"},
    {"source": "/FileEncryptor.log", "destination": "/DSS/"},
    {"source": "/canonizer.config.xml", "destination": "/DSS/"},
    {"source": "/EndPointServer.config.xml", "destination": "/DSS/"},
    {"source": "/extractor.config.xml", "destination": "/DSS/"},
    {"source": "/extractorlinux.config.xml", "destination": "/DSS/"},
    {"source": "/FingerprintRepositoryStatistics.xml", "destination": "/DSS/"},
    {"source": "/FPR.config.xml", "destination": "/DSS/"},
    {"source": "/mgmtd.config.xml", "destination": "/DSS/"},
    {"source": "/mng-repo.xml", "destination": "/DSS/"},
    {"source": "/OCRServer.config.xml", "destination": "/DSS/"},
    {"source": "/OCRServer.dynamic.config.xml", "destination": "/DSS/"},
    {"source": "/PolicyEngine.config.xml", "destination": "/DSS/"},
    {"source": "/PolicyEngine.policy.xml", "destination": "/DSS/"},
    {"source": "/PolicyEngine.policy.xml.bak", "destination": "/DSS/"},
    {"source": "/PolicyEngineStatistics.xml", "destination": "/DSS/"},
    {"source": "/ServerCapabilities.xml", "destination": "/DSS/"},
    {"source": "/packages/Services/WorkSchedulerConfig.xml", "destination": "/DSS/"}
  ],
  "WINDOWS": [
    {"source": "C:/Windows/System32/winevt/Logs/Application.evtx", "destination": "/Windows/"},
    {"source": "C:/Windows/System32/winevt/Logs/System.evtx", "destination": "/Windows/"}
  ],
  "COMMANDS": [
    {"command": "systeminfo", "output": "/Windows/systeminfo.txt"},
    {"command": "gpresult /R /Z", "output": "/Windows/gpresult.txt"},
    {"command": "netstat -abno", "output": "/Windows/netstat.txt"},
    {"command": "sc qc DSSMANAGER 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc EIPMANAGER 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc MSSQLSERVER 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc PAFPREP 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc POLICYENGINE 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc DSSBATCHSERVER 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc DSSMESSAGEBROKER 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc EPSERVER 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc WORKSCHEDULER 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc MGMTD 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc PGSQLEIP 5000", "output": "/Windows/services.txt"},
    {"command": "sc qc EIPMANAGERPROXY 5000", "output": "/Windows/services.txt"},
    {"command": "wmic os get DataExecutionPrevention_SupportPolicy", "output": "/Windows/DEP.txt"},
    {"command": "wmic computersystem get TotalPhysicalMemory /Value", "output": "/Windows/memory.txt"},
    {"command": "wmic cpu get Name, NumberOfCores, NumberOfLogicalProcessors", "output": "/Windows/cpu.txt"},
    {"command": "wmic logicaldisk Get Name, Size, Freespace", "output": "/Windows/hdd.txt"}
  ]
}
'''

# Create new FPASSIST directory in Windows local temp, delete old if exists
if os.path.exists(FPASSIST_DIR):
    shutil.rmtree(FPASSIST_DIR, ignore_errors=False, onerror=onerror)
    os.mkdir(FPASSIST_DIR)
else:
    os.mkdir(FPASSIST_DIR)

# Setup logger
logging.basicConfig(filename=FPASSIST_DIR + 'FPassist.log',
                    level=logging.DEBUG,
                    format='%(asctime)s [%(name)s] %(levelname)s - %(message)s',)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)


def main():
    disable_file_system_redirection().__enter__()
    logging.info(r'  ____ ___  ___  ___ ___ ___  ___ ___ _  _ _____ ')
    logging.info(r' |  __/ _ \| _ \/ __| __| _ \/ _ \_ _| \| |_   _|')
    logging.info(r' |  _| (_) |   / (__| _||  _/ (_) | || .` | | |  ')
    logging.info(r' |_|  \___/|_|_|\___|___|_|  \___/___|_|\_| |_|  ')
    logging.info('                                                  ')
    logging.info('              Support Assist v0.8.0               ')
    logging.info('                                                  ')
    print('\n')

    logging.info('Products detected: ')
    if DSS_DIR == 'NONE':
        logging.error('This system is not a Forcepoint DLP server!')
        logging.error('The Forcepoint Support Assist script will exit now.')
        sys.exit()
    else:
        logging.info(' * Forcepoint DLP: %s' % str(get_dss_version()))

    EIP_DIR = get_eip_path()
    if not EIP_DIR or EIP_DIR == 'NONE':
        logging.debug('EIP Infra registry key does not exist.')
    else:
        EIP_XML = EIP_DIR + "/EIPSettings.xml"
        logging.info(' * Forcepoint Security Manager: %s' % str(get_eip_version(EIP_XML)))

    print('\n')
    logging.info('Starting log collection ...')
    start_data_collection()

    print('\n')
    if EIP_DIR:
        connect_sql_database(EIP_XML)
    else:
        logging.info("System is not a Forcepoint Security Manager.  Skipping SQL queries.")

    decrypt_cluster_keys()

    check_dlp_debugging()

    print('\n')
    logging.info('Creating ZIP file ...')
    zipper('%s\\FPASSIST' % TMP_DIR, '%s\\FP.zip' % TMP_DIR)
    shutil.move('%s\\FP.zip' % TMP_DIR, FPARCHIVE)
    fp_archive_size = human_size(os.path.getsize(FPARCHIVE))
    print('\n')
    logging.info('ZIP file details: ')
    logging.info(' * Path: %s' % FPARCHIVE)
    logging.info(' * Size: %s' % fp_archive_size)
    print('\n')
    logging.info('Please send this file to Forcepoint Technical Support.')

    enable_file_system_redirection().__enter__()


def get_eip_path():
    try:
        hKey = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            'Software\\Wow6432Node\\Websense\\EIP Infra'
        )
        result = winreg.QueryValueEx(hKey, 'INSTALLDIR')
        return result[0]
    except WindowsError:
        return False
    except:
        logging.debug('Not a Forcepoint Security Manager Server')
        return False


def get_eip_version(EIP_XML):
    try:
        if os.path.exists(EIP_XML):
            try:
                tree = ET.parse(EIP_XML)
                content = tree.getroot()
                # Get EIP Version
                eip_version = str(content.find('Infra_Version').text)
                return eip_version
            except:
                logging.exception('Unable to read EIPSettings.xml')
    except NameError:
        logging.exception('Critical error has been encountered.')


def get_dss_version():
    try:
        areg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        akey = winreg.OpenKey(
            areg,
            'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Data Security'
            )
        result = winreg.QueryValueEx(akey, 'DisplayVersion')
        return result[0]
    except NotImplementedError:
        logging.exception('Not a Forcepoint DLP Server')


def fingerprint_repository_location():
    try:
        areg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        akey = winreg.OpenKey(
            areg,
            'SOFTWARE\\Wow6432Node\\Websense\\Data Security'
        )
        result = winreg.QueryValueEx(akey, 'RepositoryDir')
        return result[0]
    except NotImplementedError:
        logging.exception('Not a Forcepoint DLP Server')


def get_sql_settings(file):
    try:
        if os.path.exists(file):
            try:
                tree = ET.parse(file)
                content = tree.getroot()
                for LogDB in content.findall('LogDB'):
                    SQLSERVER = str(LogDB.find('Host').text)
                    SQLPORT = str(LogDB.find('Port').text)
                    SQLINSTANCE = str(LogDB.find('InstanceName').text.rstrip())
                if SQLINSTANCE == 'None' or SQLINSTANCE == '':
                    SQLSERVER = SQLSERVER
                else:
                    SQLSERVER = SQLSERVER + '\\' + SQLINSTANCE
                db_settings = [SQLSERVER, SQLPORT, SQLINSTANCE]
                return db_settings
            except OSError:
                logging.exception('Unable to read EIPSettings.xml')
                return False
        else:
            logging.exception('Unable to locate EIPSettings.xml')
            return False
    except NameError:
        logging.exception('A critical error has occurred.')
        return False


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
    DIR = '%s\\FPASSIST' % TMP_DIR
    logging.info('Running SQL scripts ...')
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
        logging.info('Completed SQL scripts.')
    except IOError:
        logging.exception('Unable to run SQL scripts.')


def connect_sql_database(file):
    current_user = str(win32api.GetUserNameEx(win32api.NameSamCompatible))
    db_host = get_sql_settings(file)
    if db_host:
        try:
            print('\n')
            logging.info('===== SQL Database =====')
            logging.info('SQL Server Host: "%s"' % db_host[0])
            logging.info('SQL Server Port: "%s"' % db_host[1])
            logging.info('SQL Server Instance: "%s"' % db_host[2])
            logging.info('Current Windows user: "%s"' % current_user)
            logging.info('Connecting to database using Windows Authentication')
            conn = pyodbc.connect(r'DRIVER={SQL Server};Server=%s;Database=wbsn-data-security;Trusted_Connection=yes;' % (db_host[0]))
            cursor = conn.cursor()
            windows_auth = True
            print('\n')
            logging.info('Successfully connected to database.')
            run_sql_scripts(cursor)
        # except pyodbc.Error:
        #     windows_auth = False
        #     print('\n')
        #     logging.exception('Could not establish connection to database via Windows Authentication for current user "%s"' % str(win32api.GetUserNameEx(win32api.NameSamCompatible)))
        #     logging.debug(sys.exc_info()[1])
        except:
            windows_auth = False
            print('\n')
            logging.exception('Could not establish connection to database via Windows Authentication for current user "%s"' % current_user)
            logging.debug(sys.exc_info()[1])

    if db_host and windows_auth is False:
        try:
            print('\n')
            logging.info('Trying SQL Authentication. Please enter valid SQL database credentials.')
            try:
                # Bind Python 2's raw_input() to Python 3's input().
                # This workaround allows input() to work for both Python 2 and Python 3 environments.
                input = raw_input
            except NameError:
                # Python 3 will raise NameError when raw_input() is called.
                # This is fine. Just pass and continue on.
                logging.debug(sys.exc_info()[1])
                pass
            sql_user = input('SQL Username: ')
            sql_passwd = getpass.getpass('SQL Password: ')
            conn = pyodbc.connect(r'DRIVER={SQL Server Native Client 11.0};SERVER=%s;DATABASE=wbsn-data-security;UID=%s;PWD=%s;' % (db_host[0], sql_user, sql_passwd))
            cursor = conn.cursor()
            print('\n')
            logging.info('Successfully connected to database as user "%s"' % sql_user)
            run_sql_scripts(cursor)
            conn.close()
        except pyodbc.Error:
            print('\n')
            logging.exception('Could not establish connection to database via SQL Authentication for user "%s"' % sql_user)
            logging.debug(sys.exc_info()[1])
        except:
            print('\n')
            logging.exception('Could not establish connection to database via SQL Authentication for user "%s"' % sql_user)
            logging.debug(sys.exc_info()[1])


def msinfo32(output):
    try:
        output_file = output + "/Windows/msinfo32.nfo"
        cmd = "msinfo32 /nfo " + output_file
        logging.info('Command: ' + cmd)
        process = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        with process.stdout:
            log_process_output(process.stdout)
        exitcode = process.wait()  # 0 means success
        logging.debug('Exit code %s - %s' % (exitcode, cmd))
        # subprocess.call(cmd)
    except:
        logging.exception('Exit code: %s - Cannot run MSInfo32!' % exitcode)


def check_dlp_debugging():
    DSS_CONF = DSS_DIR + '/conf/'
    for filename in os.listdir(DSS_CONF):
        with open(DSS_CONF + filename) as currentfile:
            text = currentfile.read()
            if 'DEBUG' in text or 'debug' in text:
                with open(FPASSIST_DIR + 'debug_enabled.txt', 'a+') as f:
                    f.write(filename + ' has debugging enabled\n')


def copy_data(src, dst):
    try:
        if os.path.isdir(src):
            try:
                # shutil.copytree(src, dst, dirs_exist_ok=True)
                # print('Copied directory ' + src)
                copy_tree(src, dst, preserve_times=1)
                logging.info('Directory: %s' % src)
            except OSError:
                logging.exception('Unable to copy directory. Skipping...')
        if os.path.isfile(src):
            try:
                shutil.copy2(src, dst)
                logging.info('File: %s' % src)
            except:
                logging.exception('Unable to copy file %s. Skipping...' % src)
    except IOError:
        logging.exception('Unable to copy from %s to %s.' % (src, dst))
        logging.exception('Please contact Forcepoint Technical Support for further assistance.')


def log_process_output(pipe):
    for line in iter(pipe.readline, ''):  # b'\n\'-separated lines
        logging.debug('Got line from subprocess: %r', line.rstrip())


def run_command(cmd, dst):
    try:
        output_file = dst
        with open(output_file, 'a+') as f:
            logging.info('Command: ' + cmd)
            subprocess.call(cmd, stdout=f)
    except:
        logging.exception('Cannot run command: ' + cmd)


def load_json_config():
    # Look for custom JSON settings
    if os.path.isfile('custom.json'):
        print('\n')
        logging.warning('Using custom JSON configuration.')
        custom_file = 'custom.json'
        with open(custom_file) as f:
            return json.loads(f.read())
    else:
        return json.loads(collect_me)


def start_data_collection(EIP_DIR=get_eip_path()):
    data_set = load_json_config()
    for category in data_set:
        if category == "EIP":
            if EIP_DIR:
                print('\n')
                logging.info('===== EIP logs =====')
                for item in data_set[category]:
                    dst_path = FPASSIST_DIR + item['destination']
                    if not os.path.exists(dst_path):
                        os.makedirs(dst_path)
                    src_path = EIP_DIR + item['source']
                    copy_data(src_path, dst_path)
            else:
                logging.debug('Not a Forcepoint Security Manager.')
        if category == "DSS":
            print('\n')
            logging.info('===== DSS logs =====')
            for item in data_set[category]:
                dst_path = FPASSIST_DIR + item['destination']
                if not os.path.exists(dst_path):
                    os.makedirs(dst_path)
                src_path = DSS_DIR + item['source']
                copy_data(src_path, dst_path)
        if category == "WINDOWS":
            print('\n')
            logging.info('===== Windows Event logs =====')
            for item in data_set[category]:
                dst_path = FPASSIST_DIR + item['destination']
                if not os.path.exists(dst_path):
                    os.makedirs(dst_path)
                src_path = item['source']
                copy_data(src_path, dst_path)
        if category == "COMMANDS":
            print('\n')
            logging.info('===== Windows Commands =====')
            msinfo32(FPASSIST_DIR)
            for item in data_set[category]:
                dst_path = FPASSIST_DIR + item['output']
                cmd = item['command']
                run_command(cmd, dst_path)


def search_in_file(phrase, file):
    searchfile = open(file, 'r')
    for line in searchfile:
        if phrase in line:
            return line


def decrypt_cluster_keys():
    print('\n')
    logging.info('===== Checking Crypto Keys =====')
    if os.path.isfile(CATPROP):
        catdawg = search_in_file('wbsn', CATPROP)
        cat = catdawg.replace('wbsn.com.pa.crypto.crypto.PAISCryptorV2.key=', '')
        cat1 = cat.split(':')
        cat2 = cat1[2] + ' ' + cat1[0] + ' ' + cat1[1]
        cat3 = cat2.replace('\n', ' ')
        os.chdir(DSS_DIR)
        command = 'jre\\bin\\java -cp jre\\lib\\ext\\fortress.jar;tomcat\\lib\\tomcat-ext.jar com.pa.tomcat.resources.DecryptPassword' + ' ' + cat3
        logging.debug('Catalina.properties: %s' % command)
        process = Popen(command, stdout=PIPE, stderr=STDOUT)
        with process.stdout:
            log_process_output(process.stdout)
        exitcode = process.wait()  # 0 means success
        logging.debug('Exit code %s - %s' % (exitcode, command))

    if os.path.exists(DSS_DIR):
        cacert = search_in_file('{4;', DSS_DIR + 'ca.cer')
        command = 'cryptotool -k 4 -d -t' + ' ' + cacert
        logging.debug('ca.cer: %s' % command)
        process = Popen(command, stdout=PIPE, stderr=STDOUT)
        with process.stdout:
            log_process_output(process.stdout)
        exitcode = process.wait()  # 0 means success
        logging.debug('Exit code %s - %s' % (exitcode, command))

    if os.path.exists(KEYS):
        os.chdir(KEYS)
        command = 'cryptotool -k 2 -g'
        logging.debug('epcluster.key: %s' % command)
        process = Popen(command, stdout=PIPE, stderr=STDOUT)
        with process.stdout:
            log_process_output(process.stdout)
        exitcode = process.wait()  # 0 means success
        logging.debug('Exit code %s - %s' % (exitcode, command))

    if os.path.isfile(JETTYXML):
        jettydawg = search_in_file('wsjf', JETTYXML)
        j1 = re.sub('<[^>]*>', '', jettydawg)
        j2 = j1.replace('\n', '')
        j3 = j2.replace(' ', '')
        j4 = j3.split(':')
        j5 = j4[2] + ' ' + j4[0] + ' ' + j4[1]
        os.chdir(DSS_DIR)
        command = 'jre\\bin\\java -cp jre\\lib\\ext\\fortress.jar;tomcat\\lib\\tomcat-ext.jar com.pa.tomcat.resources.DecryptPassword' + ' ' + j5
        logging.debug('jetty.xml: %s' % command)
        process = Popen(command, stdout=PIPE, stderr=STDOUT)
        with process.stdout:
            log_process_output(process.stdout)
        exitcode = process.wait()  # 0 means success
        logging.debug('Exit code %s - %s' % (exitcode, command))


def zipper(dir, zip_file):
    zip = zipfile.ZipFile(zip_file, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=True)
    root_len = len(os.path.abspath(dir))
    for root, _dirs, files in os.walk(dir):
        archive_root = os.path.abspath(root)[root_len:]
        for f in files:
            fullpath = os.path.join(root, f)
            archive_name = os.path.join(archive_root, f)
            zip.write(fullpath, archive_name, zipfile.ZIP_DEFLATED)
    zip.close()
    return zip_file


def human_size(input_bytes, units=['bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']):
    """ Returns a human readable string reprentation of bytes.

    Args:
        input_bytes (int): Raw bytes to be calculated.
        units (:obj:'list' of :obj:'str', optional): List of human readable byte size formats. Defaults to predefined list.

    Returns:
        String representing human readable byte size format.

    Example:
        "2048 MB"
    """
    return str(input_bytes) + units[0] if input_bytes < 1024 else human_size(input_bytes >> 10, units[1:])


if __name__ == '__main__':
    main()
