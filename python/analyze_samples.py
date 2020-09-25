# Android FinFisher samples bisection
# Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)
#
# Analyzes samples (APK or DEX files) and gives hints about the FinSpy variant.
# Automatically analyze DEX file contained into APK.

import zipfile
from tempfile import NamedTemporaryFile

import yara
import glob
import sys


def print_detections(matches, detected_file):
    if len(matches) > 0:
        print(f'{matches}:{detected_file}')


def apply_rules_on_file(bin_file, yara_rules):
    match = yara_rules.match(bin_file)
    return match


def detect(bin_file, yara_rules, parent_file=None):
    matches = apply_rules_on_file(bin_file, yara_rules)
    detected_file = bin_file

    if parent_file:
        detected_file = parent_file

    if bin_file.endswith('.apk'):
        print_detections(matches, detected_file)
        try:
            with zipfile.ZipFile(bin_file) as apk:
                with apk.open('classes.dex') as dex:
                    with NamedTemporaryFile(suffix='.dex') as dex_file:
                        dex_file.write(dex.read())
                        dex_file.seek(0)
                        detect(dex_file.name, yara_rules, bin_file)
        except zipfile.BadZipFile:
            pass
    elif bin_file.endswith('.dex'):
        if parent_file:
            detected_file += '/classes.dex'
        print_detections(matches, detected_file)


def list_apk_files(dir):
    apk_files = glob.glob(f'{dir}/**/*.apk', recursive=True)
    for apk_file in apk_files:
        yield apk_file


def list_dex_files(dir):
    dex_files = glob.glob(f'{dir}/**/*.dex', recursive=True)
    for dex_file in dex_files:
        yield dex_file


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: python {sys.argv[0]} <directory> <yara file>')
        sys.exit(1)

    directory = str(sys.argv[1])
    yara_file = str(sys.argv[2])

    yara_rules = yara.compile(yara_file)

    for dex in list_dex_files(directory):
        detect(dex, yara_rules)

    for apk in list_apk_files(directory):
        detect(apk, yara_rules)
