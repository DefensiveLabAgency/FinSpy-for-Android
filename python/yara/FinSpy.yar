rule FinSpy_ConfigInAPK : android apkhideconfig finspy
{
	meta:
		description = "Detect FinFisher FinSpy configuration in APK file. Probably the original FinSpy version."
		date = "2020/08/05"
		reference = "https://github.com/devio/FinSpy-Tools"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"

	strings:
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/

	condition:
		uint32(0) == 0x04034b50 and $re and (#re > 50)
}

rule FinSpy_DexDen : android dexhideconfig finspy
{
	meta:
		description = "Detect FinFisher FinSpy configuration in DEX file. Probably a newer FinSpy variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"

	strings:
		$config_1 = { 90 5b fe 00 }
		$config_2 = { 70 37 80 00 }
		$config_3 = { 40 38 80 00 }
		$config_4 = { a0 33 84 }
		$config_5 = { 90 79 84 00 }

	condition:
		uint16(0) == 0x6564 and
		#config_1 >= 2 and 
		#config_2 >= 2 and 
		#config_3 >= 2 and 
		#config_4 >= 2 and 
		#config_5 >= 2
}

rule FinSpy_TippyTime: finspyTT
{
	meta:
		description = "Detect FinFisher FinSpy 'TippyTime' variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"
	strings:
		$config_1 = { 90 5b fe 00 }
		$config_2 = { 70 37 80 00 }
		$config_3 = { 40 38 80 00 }
		$config_4 = { a0 33 84 }
		$config_5 = { 90 79 84 00 }
		$timestamp = { 95 E9 D1 5B }

	condition:
		uint16(0) == 0x6564 and
		$timestamp and
		$config_1 and 
		$config_2 and 
		$config_3 and 
		$config_4 and 
		$config_5
}

rule FinSpy_TippyPad: finspyTP
{
	meta:
		description = "Detect FinFisher FinSpy 'TippyPad' variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"
	strings:
		$pad_1 = "0123456789abcdef"
		$pad_2 = "fedcba9876543210"

	condition:
		uint16(0) == 0x6564 and
		#pad_1 > 50 and
		#pad_2 > 50
}
