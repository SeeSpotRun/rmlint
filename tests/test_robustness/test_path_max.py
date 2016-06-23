#!/usr/bin/env python3
# encoding: utf-8
from nose import with_setup
from tests.utils import *


@with_setup(usual_setup_func, usual_teardown_func)
def test_file():
    name1 = 'is_seen'
    name2 = 'too_long'
    create_file('xxx', name1)
    create_file('xxx', name2)
    path_max = len(TESTDIR_NAME + '/' + name2) + 1  # (+1 is for terminating null)

    head, *data, footer = run_rmlint('--pathmax', str(path_max - 1))
    assert 0 == len(data)

    head, *data, footer = run_rmlint('--pathmax', str(path_max))
    assert 2 == len(data)


@with_setup(usual_setup_func, usual_teardown_func)
def test_dir():
    name1 = 'empty1/is_seen'
    name2 = 'empty2/too_long'
    create_dirs(name1)
    create_dirs(name2)

    # +1 is for terminating null;
    # +2 is so we can read the '..' dirent as part of checking that dir is empty
    path_max = len(TESTDIR_NAME + '/' + name2 + '/') + 1 + 2 #

    head, *data, footer = run_rmlint('--pathmax', str(path_max - 1))
    assert 2 == len(data) # empty1 and empty1/is_seen

    head, *data, footer = run_rmlint('--pathmax', str(path_max))
    assert 5 == len(data) # all 4 created dirs plus the testdir itself

@with_setup(usual_setup_func, usual_teardown_func)
def test_passed():

    # test for vulnerabilities / OBOB for passed paths close to path_max
    # not looking for any results, just a chance to detect valgrind errors
    create_file('xxx', 'a')

    path_max = len(TESTDIR_NAME + '/') + 1  # (+1 for null)
    head, *data, footer = run_rmlint('--pathmax', str(path_max))
    assert 0 == len(data)
    head, *data, footer = run_rmlint('--pathmax', str(path_max - 1))
    assert 0 == len(data)
    head, *data, footer = run_rmlint('--pathmax', str(path_max + 1))
    assert 0 == len(data)
