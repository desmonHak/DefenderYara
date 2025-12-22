
rule Trojan_Win32_GuLoader_SVB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 79 6f 67 69 73 5c 61 70 6f 74 65 6b 73 61 73 73 69 73 74 65 6e 74 65 72 6e 65 } //1 \yogis\apoteksassistenterne
		$a_81_1 = {5c 70 61 61 6b 6c 61 67 65 64 65 5c 62 75 64 67 65 74 72 6f 64 65 74 2e 69 6e 69 } //1 \paaklagede\budgetrodet.ini
		$a_81_2 = {5c 75 73 6b 6e 6e 65 2e 7a 69 70 } //1 \usknne.zip
		$a_81_3 = {47 69 67 61 6e 74 69 73 6b 2e 74 78 74 } //1 Gigantisk.txt
		$a_81_4 = {4c 6f 6e 67 77 69 6e 64 65 64 2e 71 75 61 } //1 Longwinded.qua
		$a_81_5 = {69 6e 74 65 72 69 6d 73 6b 76 69 74 74 65 72 69 6e 67 65 6e 73 2e 6d 61 6b } //1 interimskvitteringens.mak
		$a_81_6 = {72 69 64 65 62 61 6e 65 73 70 72 69 6e 67 6e 69 6e 67 2e 6a 70 67 } //1 ridebanespringning.jpg
		$a_81_7 = {5c 67 65 6f 67 72 61 66 69 73 6b 65 2e 74 78 74 } //1 \geografiske.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}