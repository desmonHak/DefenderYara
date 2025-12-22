
rule Trojan_Win32_GuLoader_SUP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 4d 65 67 61 70 74 65 72 69 6e 65 31 30 39 2e 69 6e 69 } //1 \Megapterine109.ini
		$a_81_1 = {5c 70 72 6f 64 75 6b 74 69 76 69 74 65 74 5c 47 61 6c 76 61 6e 6f 70 73 79 63 68 69 63 } //1 \produktivitet\Galvanopsychic
		$a_81_2 = {5c 64 6f 77 6c 2e 74 78 74 } //1 \dowl.txt
		$a_81_3 = {4f 70 61 63 69 74 65 2e 48 6f 6d } //1 Opacite.Hom
		$a_81_4 = {44 64 74 31 37 2e 68 6f 6d } //1 Ddt17.hom
		$a_81_5 = {61 72 62 65 6a 64 73 66 75 6e 6b 74 69 6f 6e 2e 69 63 68 } //1 arbejdsfunktion.ich
		$a_81_6 = {6b 61 73 6b 61 64 65 73 2e 67 6c 65 } //1 kaskades.gle
		$a_81_7 = {72 65 77 72 69 74 65 2e 77 68 69 } //1 rewrite.whi
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}