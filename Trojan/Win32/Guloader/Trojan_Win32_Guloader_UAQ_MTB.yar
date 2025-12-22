
rule Trojan_Win32_Guloader_UAQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.UAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {42 65 74 61 6c 69 6e 67 73 62 65 74 69 6e 67 65 6c 73 65 72 6e 65 73 2e 68 6f 6e } //1 Betalingsbetingelsernes.hon
		$a_81_1 = {54 79 72 6f 6c 65 72 65 6e 73 2e 73 69 74 } //1 Tyrolerens.sit
		$a_81_2 = {61 66 74 6a 65 6e 69 6e 67 65 72 2e 70 61 72 } //1 aftjeninger.par
		$a_81_3 = {61 6d 70 68 69 6d 61 63 65 72 2e 72 61 64 } //1 amphimacer.rad
		$a_81_4 = {73 6b 72 61 61 73 74 69 6c 6c 69 6e 67 65 72 73 5c 6b 6f 6e 74 72 61 73 74 65 72 6e 65 73 } //1 skraastillingers\kontrasternes
		$a_81_5 = {72 6f 74 75 6e 64 69 66 79 5c 6d 61 72 6b 65 64 73 64 61 67 65 6e 65 73 5c 73 72 67 6d 75 6e 74 65 72 } //1 rotundify\markedsdagenes\srgmunter
		$a_81_6 = {5c 6d 69 74 72 65 5c 66 61 76 72 70 72 69 73 65 72 5c 74 61 72 73 6f 70 6c 61 73 69 61 } //1 \mitre\favrpriser\tarsoplasia
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}