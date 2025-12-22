
rule Trojan_Win64_Midie_GVA_MTB{
	meta:
		description = "Trojan:Win64/Midie.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 45 d8 48 83 7d f0 0f 48 0f 47 45 d8 0f b6 14 08 80 f2 3d 48 8b c6 48 83 7e 18 0f 76 03 48 8b 06 88 14 08 48 ff c1 48 3b 4d e8 72 d2 } //2
		$a_01_1 = {2f 2f 74 61 70 70 65 64 2e 77 69 6e 2f } //1 //tapped.win/
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 43 48 41 52 4d 5c 41 75 74 68 } //1 SOFTWARE\CHARM\Auth
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}