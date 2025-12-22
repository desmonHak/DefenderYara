
rule Ransom_MSIL_HiddenTear_GVA_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {1f 14 16 03 19 28 02 00 00 06 26 2a } //2
		$a_00_1 = {5c 00 52 00 65 00 61 00 64 00 20 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 \Read Me.txt
		$a_00_2 = {2f 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 2e 00 74 00 78 00 74 00 } //1 /message.txt
		$a_00_3 = {70 00 6f 00 73 00 74 00 2e 00 70 00 68 00 70 00 } //1 post.php
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}