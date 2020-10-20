# Android FinFisher samples bisection
# Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)
#
# Analyzes samples (APK or DEX files) and gives hints about the FinSpy variant.
# Automatically analyze DEX file contained into APK and extract FinSpy configuration (DexDen only).
import shutil
import zipfile
from tempfile import NamedTemporaryFile

from objutils import Section

import yara
import glob
import json
import sys
import os

from config_parser import parse_dex_configuration, parse_configuration_entries, find_config_entry
from extract_apk_config import extract_apk_config


class FinSpyAnalyzer:
    def __init__(self, sample, output_dir, yara_file):
        self.sample = sample
        self.main_output_dir = output_dir
        self.dump_dir = None
        self.raw_config = None
        self.parsed_config = None
        self.config_addr = 0
        self.matches = []
        self.yara_rules = yara.compile(yara_file)
        # self.apply_rules()

    def summary(self):
        line = self.sample + '\n'
        line += f'Matching Yara rules: {self.matches}\n'
        line += 'FinSpy configuration: '
        if self.raw_config and self.parsed_config:
            line += 'found and extracted\n'
        else:
            line += 'not found\n'
        return line + '\n'

    def _prepare_output(self):
        output_path = os.path.realpath(self.main_output_dir)
        if not os.path.exists(output_path):
            os.mkdir(output_path)
        origin_file_name_path = os.path.join(output_path, os.path.basename(self.sample))
        if not os.path.exists(origin_file_name_path):
            os.mkdir(origin_file_name_path)

        self.dump_dir = origin_file_name_path

    def dump(self):
        if self.raw_config and self.parsed_config:
            self._prepare_output()
            with open(os.path.join(self.dump_dir, 'config.json'), 'w') as out:
                json.dump(self.parsed_config, out, indent=2, sort_keys=True)
            with open(os.path.join(self.dump_dir, 'config.dat'), 'wb') as out:
                out.write(self.raw_config)
            with open(os.path.join(self.dump_dir, 'config.hex'), 'w') as out:
                section = Section(self.config_addr, self.raw_config)
                section.hexdump(out)
            with open(os.path.join(self.dump_dir, 'config.txt'), 'w') as out:
                for i in self.parsed_config:
                    elt = i
                    line = '['+str(elt.get('tlv_int'))+']'
                    line += '['+elt.get('tlv_hex')+']'
                    line += ' '+elt.get('tlv_name')+' = '
                    if elt['attrs']:
                        for a in elt['attrs']:
                            line += '\n - ' + a['name'] + ': ' + str(a['active'])
                        line += '\n'
                    elif elt['is_printable_value']:
                        line += str(elt.get('value'))
                    else:
                        line += '\n'+elt.get('value')
                    out.write(line+'\n')

    @staticmethod
    def print_detections(matches, detected_file):
        if len(matches) > 0:
            print(f'{matches}:{detected_file}')

    def apply_rules(self):
        self.matches = self.yara_rules.match(self.sample)

    def detect(self, bin_file, parent_file=None):
        self.matches += self.yara_rules.match(bin_file)
        detected_file = bin_file

        if parent_file:
            detected_file = parent_file

        if bin_file.endswith('.apk'):
            # self.print_detections(matches, detected_file)
            if 'FinSpy_ConfigInAPK' in [m.rule for m in self.matches]:
                with open(bin_file, 'rb') as apk_file:
                    config = extract_apk_config(apk_file.read())
                    if config:
                        self.raw_config = config
                        self.config_addr = 12
                        self.parsed_config = parse_configuration_entries(config, 12, len(config))
            try:
                with zipfile.ZipFile(bin_file) as apk:
                    with apk.open('classes.dex') as dex:
                        with NamedTemporaryFile(suffix='.dex') as dex_file:
                            dex_file.write(dex.read())
                            dex_file.seek(0)
                            self.detect(dex_file.name, bin_file)
            except zipfile.BadZipFile:
                pass
        elif bin_file.endswith('.dex'):
            if parent_file:
                detected_file += '/classes.dex'
            # self.print_detections(matches, detected_file)
            if 'FinSpy_DexDen' in [m.rule for m in self.matches]:
                try:
                    with open(bin_file, 'rb') as dex_file:
                        dex_data = dex_file.read()
                        offset, length = find_config_entry(dex_data)
                        self.raw_config = dex_data[offset:offset+length]
                        self.config_addr = offset
                        self.parsed_config = parse_dex_configuration(bin_file)
                except:
                    pass

    @staticmethod
    def list_apk_files(dir):
        apk_files = glob.glob(f'{dir}/**/*.apk', recursive=True)
        for apk_file in apk_files:
            yield apk_file

    @staticmethod
    def list_dex_files(dir):
        dex_files = glob.glob(f'{dir}/**/*.dex', recursive=True)
        for dex_file in dex_files:
            yield dex_file


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f'Usage: python {sys.argv[0]} <directory> <yara file> <output_dir>')
        sys.exit(1)

    directory = str(sys.argv[1])
    yara_file = str(sys.argv[2])
    output_dir = str(sys.argv[3])

    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.mkdir(output_dir)

    def _do(dex, output_dir, yara_file):
        analyzer = FinSpyAnalyzer(dex, output_dir, yara_file)
        analyzer.detect(dex)
        analyzer.dump()
        # print(analyzer.summary())
        with open(os.path.join(output_dir, 'summary.txt'), 'a') as s:
            s.write(analyzer.summary())

    for dex in FinSpyAnalyzer.list_dex_files(directory):
        _do(dex, output_dir, yara_file)

    for apk in FinSpyAnalyzer.list_apk_files(directory):
        _do(apk, output_dir, yara_file)
