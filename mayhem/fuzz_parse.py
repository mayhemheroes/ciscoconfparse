#!/usr/bin/env python3

import atheris
import io
import sys
import logging
import warnings
from contextlib import contextmanager

import fuzz_helpers


with atheris.instrument_imports(include=['ciscoconfparse']):
    from ciscoconfparse import CiscoConfParse

logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")
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
    factory = fdp.ConsumeBool()
    config_stmts = fdp.ConsumeRemainingString().splitlines()
    try:
        with nostdout():
            CiscoConfParse(config_stmts, factory=factory, syntax=syntax, comment=delimiter)
    except (AssertionError, NotImplementedError, IndexError):
        return -1
    except ValueError as e:
        if 'Could not find' in str(e):
            return -1
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
