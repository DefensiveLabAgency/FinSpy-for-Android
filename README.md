# FinSpy for Android tools - 2020
This repository contains the tools we developed while investigating on **a new FinSpy implant for Android** as explained in [the AmnestyTech report](https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/) and [our analysis report](https://defensive-lab.agency/2020/09/finspy-android/).

These tools are meant to:
* extract and decode obfuscated strings;
* extract and parse configuration whether it is stored into the APK or into the DEX.

## FinSpy variants detection
We provide Yara rules (located at `python/yara`) detecting 4 variations of FinSpy for Android:
* `FinSpy_ConfigInAPK`: FinSpy configuration stored into the APK
* `FinSpy_DexDen`: FinSpy configuration stored into the DEX
* `FinSpy_TippyTime`: use of a timestamp to generate local socket address
* `FinSpy_TippyPad`: use of basic pad to obfuscate strings

## Tools overview
* `java_parser.py` extracts `FinSpy_TippyPad` obfuscated strings from Java source code
* `string_decoder.py` decodes obfuscated strings
* `analyze_samples.py` detects, extracts and parses FinSpy configuration of all samples stored in a given directory

NB: `analyze_samples.py` extracts and parses configuration whether it is stored into the APK or into the DEX.

## Installation
* clone this repository: `git clone https://github.com/DefensiveLabAgency/FinSpy-for-Android.git`
* enter into the cloned directory: `cd FinSpy-for-Android.git`
* create a Python 3 virtual env.: `virtualenv -p python3 venv`
* activate the venv: `source venv/bin/activate`
* play!

## Configuration parsing
The scripts we provide parse what we were able to reverse so few configuration fields are not parsed. Anyway, if you run `python analyze_samples.py ../samples yara/FinSpy.yar output`, the script will generate the following directory structure:
* `output/` 
  * `summary.txt` an analysis summary report
  * `<sample name>/`
    * `config.dat` raw extracted configuration
    * `config.hex` hexdump of the extracted configuration
    * `config.json` JSON representation of the parsed configuration
    * `config.txt` text representation of the parsed configuration

## Examples
Example of summary:
```
../samples/WIFI.apk
Matching Yara rules: [FinSpy_DexDen, FinSpy_TippyTime, FinSpy_TippyPad]
FinSpy configuration: found and extracted

../samples/9c8bf89d043ba3ed802d6d4f9b290747d12822402d61065adfbcb48a740a47b8.apk
Matching Yara rules: [FinSpy_DexDen, FinSpy_TippyTime, FinSpy_TippyPad]
FinSpy configuration: found and extracted
```

Example of parsed configuration:
```
[...]
[8402800][803770] TlvTypeConfigTargetProxy = 185.[redacted]
[8402800][803770] TlvTypeConfigTargetProxy = 103.[redacted]
[8403008][803840] TlvTypeConfigTargetPort = 443
[8676208][846370] TlvTypeConfigSMSPhoneNumber = +04[redacted]
[8676976][846670] TlvTypeMobileTrojanID = 12[redacted]
[8676672][846540] TlvTypeMobileTrojanUID = 22[redacted]
[16654656][fe2140] TlvTypeUserID = 1000
[8392000][800d40] TlvTypeTrojanMaxInfections = 9
[8677440][846840] TlvTypeConfigMobileAutoRemovalDateTime = 0
[8403776][803b40] TlvTypeConfigAutoRemovalIfNoProxy = 168
[8675472][846090] TlvTypeMobileTargetHeartbeatEvents = 
 - SIM changed: True
 - Cell location changed: False
 - Network changed: True
 - Call: False
 - Wifi connected: True
 - Data link available: True
 - Network activated: False
 - Data available: True
[8681872][847990] TlvTypeInstalledModules = 
 - Spy calls: False
 - Intercept calls: False
 - SMS: True
 - Address book: True
 - Logging: False
 - Location: True
 - Call log: True
 - Calendar: True
 - Spy chats: True
[...]
```
    
## Credits
* Esther Onfroy
* Etienne Maynier