
rule Trojan_BAT_Remcos_MCG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 17 58 07 8e 69 5d 0c 11 20 20 [0-10] 61 } //2
		$a_01_1 = {43 53 56 56 69 65 77 65 72 2e 46 6f 72 6d 73 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 } //1 CSVViewer.Forms.MainForm.resource
		$a_01_2 = {57 9d a2 29 09 0b 00 00 00 fa 25 33 00 16 00 00 01 } //1
		$a_01_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}