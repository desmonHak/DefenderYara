
rule Trojan_Win32_GuLoader_SUM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 61 6c 6d 65 6e 68 65 64 65 6e 73 } //1 \almenhedens
		$a_81_1 = {5c 46 6c 6f 6b 61 74 69 73 35 38 2e 69 6e 69 } //1 \Flokatis58.ini
		$a_81_2 = {5c 44 69 76 65 72 74 69 6c 61 } //1 \Divertila
		$a_81_3 = {5c 62 65 61 72 65 72 2e 69 6e 69 } //1 \bearer.ini
		$a_81_4 = {62 6f 6e 6b 61 6d 6d 65 72 61 74 65 72 73 2e 66 6c 69 } //1 bonkammeraters.fli
		$a_81_5 = {6f 76 65 72 6f 72 64 65 6e 74 6c 69 67 65 73 2e 67 75 6c } //1 overordentliges.gul
		$a_81_6 = {6f 76 65 72 70 72 73 69 64 69 65 74 73 2e 74 69 6e } //1 overprsidiets.tin
		$a_81_7 = {73 69 72 6b 69 2e 6b 75 65 } //1 sirki.kue
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}