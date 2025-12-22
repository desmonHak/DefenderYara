
rule Trojan_Win32_Fareit_BC_MTB{
	meta:
		description = "Trojan:Win32/Fareit.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 55 ef 33 94 85 e0 fb ff ff 88 16 ?? ?? ?? ?? 46 ff 4d e0 0f 85 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}