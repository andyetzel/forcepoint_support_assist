#!/usr/bin/env python

"""Tests for `forcepoint_support_assist` package."""

import pytest


from forcepoint_support_assist import forcepoint_support_assist


@pytest.fixture
def response():
    """Sample pytest fixture.

    See more at: http://doc.pytest.org/en/latest/fixture.html
    """
    # import requests
    # return requests.get('https://github.com/audreyr/cookiecutter-pypackage')


def test_content(response):
    """Sample pytest test function with the pytest fixture as an argument."""
    # from bs4 import BeautifulSoup
    # assert 'GitHub' in BeautifulSoup(response.content).title.string

def test_get_eip_path():
    # with pytest.raises(WindowsError):
    pass


def test_get_eip_version(EIP_XML):
    # with pytest.raises(NameError):
    pass


def test_get_dss_verison():
    # with pytest.raises(NotImplementedError):
    pass


def test_fingerprint_repository_location():
    pass


def test_get_sql_settings(file):
    # with pytest.raises(OSError):
    # with pytest.raises(NameError):
    pass


def test_run_sql_scripts(db_cursor):
    # with pytest.raises(IOError):
    pass


def test_connect_sql_database(file):
    pass


def test_msinfo32(output):
    pass


def test_check_dlp_debugging():
    pass


def test_copy_data(src, dst):
    pass


def test_log_process_output(pipe):
    pass


def test_run_command(cmd, dst):
    pass


def test_load_json_config():
    pass


def test_start_data_collection(EIP_DIR):
    pass


def test_search_in_file(phrase, file):
    pass


def test_decrypt_cluster_keys():
    pass


def test_zipper(dir, zip_file):
    pass


def test_human_size(input_bytes, units=['bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']):
    pass


def test_main():
    pass