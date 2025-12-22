
rule Trojan_Win32_GuLoader_SVA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 6f 75 74 73 74 61 6e 64 65 72 5c 74 6f 70 6f 70 6f 6c 69 74 61 6e 2e 6a 70 67 } //1 \outstander\topopolitan.jpg
		$a_81_1 = {42 61 73 65 6d 6f 64 65 6d 31 32 39 2e 6f 70 76 } //1 Basemodem129.opv
		$a_81_2 = {49 6e 64 6c 61 61 6e 73 34 33 2e 64 61 61 } //1 Indlaans43.daa
		$a_81_3 = {54 72 69 73 74 69 63 68 6f 75 73 2e 74 61 6c } //1 Tristichous.tal
		$a_81_4 = {64 6f 6b 75 6d 65 6e 74 61 72 67 72 75 70 70 65 2e 63 61 6c } //1 dokumentargruppe.cal
		$a_81_5 = {66 69 72 65 61 72 6d 73 2e 70 79 72 } //1 firearms.pyr
		$a_81_6 = {68 65 6d 69 68 79 64 72 6f 73 69 73 2e 6f 72 6c } //1 hemihydrosis.orl
		$a_81_7 = {5c 44 69 72 65 6b 74 69 6f 6e 65 6e 32 31 38 5c 46 6c 6f 77 65 72 70 65 63 6b 65 72 2e 74 78 74 } //1 \Direktionen218\Flowerpecker.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}