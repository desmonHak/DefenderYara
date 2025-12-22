
rule Trojan_Win32_GuLoader_SVO_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 42 6c 61 6e 64 65 72 65 6e 2e 6c 6e 6b } //1 \Blanderen.lnk
		$a_81_1 = {5c 74 72 6b 61 73 73 65 72 6e 65 5c 73 63 61 6d 65 6c 2e 6a 70 67 } //1 \trkasserne\scamel.jpg
		$a_81_2 = {5c 4e 6f 6e 73 6f 6c 75 62 6c 79 5c 68 6f 74 6d 6f 75 74 68 65 64 2e 69 6e 69 } //1 \Nonsolubly\hotmouthed.ini
		$a_81_3 = {5c 64 69 73 68 77 61 73 68 65 72 2e 69 6e 69 } //1 \dishwasher.ini
		$a_81_4 = {5c 53 65 61 6c 69 6b 65 31 38 5c 63 6f 6c 6f 72 66 75 6c 6c 79 2e 6a 70 67 } //1 \Sealike18\colorfully.jpg
		$a_81_5 = {5c 69 6e 74 65 72 63 6f 6d 70 61 72 65 2e 7a 69 70 } //1 \intercompare.zip
		$a_81_6 = {41 72 72 6f 67 61 74 65 73 32 31 35 2e 64 6f 72 } //1 Arrogates215.dor
		$a_81_7 = {53 70 69 72 69 74 75 73 62 65 73 6b 61 74 6e 69 6e 67 65 6e 32 34 30 2e 61 6e 75 } //1 Spiritusbeskatningen240.anu
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}