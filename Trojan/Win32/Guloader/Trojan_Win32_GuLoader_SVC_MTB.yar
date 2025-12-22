
rule Trojan_Win32_GuLoader_SVC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 6f 62 73 69 64 65 5c 4d 61 67 6e 65 74 65 72 2e 69 6e 69 } //1 \obside\Magneter.ini
		$a_81_1 = {6c 61 76 70 72 69 73 76 61 72 65 68 75 73 65 2e 74 78 74 } //1 lavprisvarehuse.txt
		$a_81_2 = {5c 66 72 61 66 61 6c 64 73 70 72 6f 63 65 6e 74 2e 6a 70 67 } //1 \frafaldsprocent.jpg
		$a_81_3 = {41 63 68 6f 6e 64 72 69 74 69 63 31 30 32 2e 66 69 6d } //1 Achondritic102.fim
		$a_81_4 = {41 73 74 72 61 6b 61 6e 2e 74 78 74 } //1 Astrakan.txt
		$a_81_5 = {42 65 67 6c 6f 6f 6d 73 2e 6f 75 74 } //1 Beglooms.out
		$a_81_6 = {42 72 79 73 74 68 75 6c 65 73 31 37 37 2e 65 6b 76 } //1 Brysthules177.ekv
		$a_81_7 = {45 6b 73 70 72 6f 70 72 69 65 72 69 6e 67 73 70 6c 61 6e 2e 73 74 6a } //1 Eksproprieringsplan.stj
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}