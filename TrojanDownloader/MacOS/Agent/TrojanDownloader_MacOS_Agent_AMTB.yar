
rule TrojanDownloader_MacOS_Agent_AMTB{
	meta:
		description = "TrojanDownloader:MacOS/Agent!AMTB,SIGNATURE_TYPE_MACHOHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_80_0 = {35 31 39 30 65 66 31 37 33 33 31 38 33 61 30 64 63 36 33 66 62 36 32 33 33 35 37 66 35 36 64 36 } //5190ef1733183a0dc63fb623357f56d6  1
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 25 40 2f 64 79 6e 61 6d 69 63 } //https://%@/dynamic  3
		$a_80_2 = {2f 74 6d 70 2f 74 65 73 74 2e 73 63 70 74 } ///tmp/test.scpt  3
		$a_80_3 = {2f 74 6d 70 2f 6f 73 61 6c 6f 67 67 69 6e 67 2e 7a 69 70 } ///tmp/osalogging.zip  1
		$a_80_4 = {68 74 74 70 73 3a 2f 2f 25 40 2f 67 61 74 65 } //https://%@/gate  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=9
 
}