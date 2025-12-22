
rule Trojan_Win32_Fareit_BF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 02 88 45 ?? 89 db 90 90 90 90 90 90 90 90 90 90 90 90 81 fb ff 00 00 00 76 } //2
		$a_03_1 = {33 d2 8a 55 ?? 33 c2 3d ff 00 00 00 76 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}