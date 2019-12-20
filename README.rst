=========================
Forcepoint Support Assist
=========================






Forcepoint Support Assist is a python script used to automate data collection of logs for Forcepoint DLP.

This script is based on the original SerVerinfoOS (SVOS) script hosted on the Forcepoint TEG Wiki_

.. _Wiki: http://ssdengwiki1.websense.com/doku.php?id=wiki:tools&s[]=svos#svos_serverinfoos



Features
--------
* Currently supported only on Windows-based servers:
    - Forcepoint Security Manager
    - Secondary DLP Servers
* Compatible with Python 2.x and Python 3.x environments

Releases
--------

* v0.1.0
    Initial release

* v0.1.1
    Fixed an issue causing script to exit prematurely due to permission issue with DSS apache logs.

* v0.1.2
    Fixed IndexError when parsing EIPSettings.xml due to changes introduced in EIP v8.5.2.

* v0.1.3
    Added Python 3.x compatibility for changes in v0.1.2 release.
    Fixed typos in output.
    Updated documentation.

* v0.2.0
    Refactored code for readability and maintainability

* v0.3.0
    Added debug logging capability

* v0.4.0
    Refactored logic for multiple subprocess calls

* v0.5.0
    Refactored decrypt cluster keys
    Added Forcepoint Banner
    Changed some output verbiage

* v0.5.1
    Fixed NameError for non-existent EIPSettings.xml when running on supplemental DLP server
    Fixed TypeError for bad variable type concatenation when running on supplemental DLP server

* v0.6.0
    Added advanced logging capability
    Fixed multiple issues for some uncaught exceptions

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
