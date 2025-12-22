
rule HackTool_AndroidOS_WifiCrack_D_MTB{
	meta:
		description = "HackTool:AndroidOS/WifiCrack.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 69 62 72 70 6c 75 73 2f 4d 6f 6e 69 74 6f 72 41 63 74 69 76 69 74 79 } //2 wibrplus/MonitorActivity
		$a_01_1 = {77 69 62 72 70 6c 75 73 2f 57 69 66 69 53 63 61 6e 41 63 74 69 76 69 74 79 } //2 wibrplus/WifiScanActivity
		$a_01_2 = {57 49 42 52 3a 77 69 66 69 6c 6f 63 6b } //1 WIBR:wifilock
		$a_01_3 = {4c 63 7a 2f 61 75 72 61 64 65 73 69 67 6e 2f 77 69 62 72 70 6c 75 73 2f 42 72 75 74 65 66 6f 72 63 65 47 65 6e 65 72 61 74 6f 72 } //1 Lcz/auradesign/wibrplus/BruteforceGenerator
		$a_01_4 = {62 72 75 74 65 66 6f 72 63 65 47 65 6e 65 72 61 74 6f 72 } //1 bruteforceGenerator
		$a_01_5 = {55 50 44 41 54 45 20 62 72 75 74 65 66 6f 72 63 65 20 53 45 54 20 6c 61 73 74 50 61 73 73 77 6f 72 64 3d } //1 UPDATE bruteforce SET lastPassword=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}