import struct
import re
import base64
"""
Decode configuration from Android
Python3 only
"""

__author__ = "Etienne Maynier"


def extract_apk_config(data):
    """
    Extract configuration from apks
    Based on
    https://github.com/SpiderLabs/malware-analysis/tree/master/Ruby/FinSpy
    https://github.com/devio/FinSpy-Tools/blob/master/Android/finspyCfgExtract.py
    """
    b64 = ''
    for zf in re.finditer(b'PK\x01\x02', data):
        pos = zf.span()[0]
        try:
            id, \
            version, host_os, min_version, target_os, \
            gp_flags, compression_method, \
            file_time, file_crc, file_size_compressed, file_size_uncompressed, \
            filename_len, extrafield_len, comment_len, disk_number, \
            hidden_data, \
            local_hdr_offset = struct.unpack("<I4c2H4I4H6sI", data[pos:pos+46])
            internal_bm, external_bm = struct.unpack("<HI", hidden_data)
        except Exception as e:
            pass
        else:
            #return None
            if (internal_bm & 0xfffa) > 0:
                try:
                    hd = hidden_data.decode('utf-8').strip("\x00")
                    if hd.isprintable():
                        b64 += hd
                except UnicodeDecodeError:
                    pass

    if b64 == '':
        return None
    else:
        try:
            return base64.b64decode(b64)
        except Exception:
            return None
