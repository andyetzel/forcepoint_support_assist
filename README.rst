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
    Hotfix - Fixed an issue causing script to exit prematurely due to permission issue with DSS apache logs

* v0.1.2
    Hotfix - Fixed IndexError when parsing EIPSettings.xml due to changes introduced in EIP v8.5.2.

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
