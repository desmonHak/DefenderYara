
rule Trojan_Win32_GuLoader_SUW_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5c 71 75 69 70 70 79 2e 74 78 74 } //1 \quippy.txt
		$a_81_1 = {5c 76 65 73 74 76 67 67 65 6e 73 2e 68 74 6d } //1 \vestvggens.htm
		$a_81_2 = {5c 73 74 79 6c 65 2e 4e 69 67 } //1 \style.Nig
		$a_81_3 = {5c 74 68 72 65 73 68 65 6c 5c 74 72 69 6d 65 6c 6c 69 74 69 63 2e 69 6e 69 } //1 \threshel\trimellitic.ini
		$a_81_4 = {56 61 6c 6d 75 65 66 72 73 2e 4f 76 65 } //1 Valmuefrs.Ove
		$a_81_5 = {41 66 70 72 69 6b 2e 74 78 74 } //1 Afprik.txt
		$a_81_6 = {43 65 6e 74 72 61 6c 69 73 65 72 65 74 2e 6a 70 67 } //1 Centraliseret.jpg
		$a_81_7 = {44 65 63 61 72 62 6f 6e 79 6c 61 74 69 6e 67 2e 69 6e 69 } //1 Decarbonylating.ini
		$a_81_8 = {54 65 64 65 73 63 61 2e 6a 70 67 } //1 Tedesca.jpg
		$a_81_9 = {6f 70 62 65 76 61 72 69 6e 67 73 6b 61 70 61 63 69 74 65 74 65 72 6e 65 73 2e 74 78 74 } //1 opbevaringskapaciteternes.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}