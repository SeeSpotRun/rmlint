#!/usr/bin/env python3
# encoding: utf-8
from nose import with_setup
from tests.utils import *


@with_setup(usual_setup_func, usual_teardown_func)
def test_path_max():
    create_file('xxx', 'folder/ok_file')
    create_file('xxx', 'folder/too_long')
    create_dirs(       'empty/ok_dir_')   # dirs need one more char for trailing '/'
    create_dirs(       'empt2/too_long')

    path_max = len(TESTDIR_NAME + '/folder/ok_file') + 1  # (+1 is for terminating null)


    # first test won't be able to stat the 'too_long' files
    head, *data, footer = run_rmlint('--pathmax', str(path_max))
    assert 2 == len(data)
    assert 2 == sum(find['type'] == 'emptydir' for find in data)  # empty and empty/ok_dir_


    # first test adds 1 character to path_max and should run ok
    head, *data, footer = run_rmlint('--pathmax', str(path_max + 1))
    assert 6 == len(data)
    assert 4 == sum(find['type'] == 'emptydir' for find in data)
    assert 2 == sum(find['type'] == 'duplicate_file' for find in data)


    # test for vulnerabilities / OBOB for passed paths close to path_max
    path_max = len(TESTDIR_NAME) + 1  # (+1 is for terminating null)
    head, *data, footer = run_rmlint('--pathmax', str(path_max))
    assert 0 == len(data)

    head, *data, footer = run_rmlint('--pathmax', str(path_max - 1))
    assert 0 == len(data)

    head, *data, footer = run_rmlint('--pathmax', str(path_max + 1))
    assert 0 == len(data)
