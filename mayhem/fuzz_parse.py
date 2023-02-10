#!/usr/bin/env python3

import atheris
import io
import sys
import logging
import loguru
import warnings
from contextlib import contextmanager

import fuzz_helpers


with atheris.instrument_imports(include=['ciscoconfparse']):
    from ciscoconfparse import CiscoConfParse

loguru.logger.remove()

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr


syntax_to_delimiter = {'ios': '!',
                       'nxos': '!',
                       'asa': '"',
                       'junos': '/',
                       'terraform': '#'}
syntaxes = list(syntax_to_delimiter.keys())


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    syntax = fdp.PickValueInList(syntaxes)
    delimiter = syntax_to_delimiter[syntax]
    config_stmts = fdp.ConsumeRemainingString().splitlines()
    try:
        with nostdout():
            CiscoConfParse(config_stmts, syntax=syntax, comment=delimiter)
    except (AssertionError, NotImplementedError, AttributeError, ValueError):
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
