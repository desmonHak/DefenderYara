
rule Trojan_Win32_Fareit_EOKI_MTB{
	meta:
		description = "Trojan:Win32/Fareit.EOKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8a 55 f3 33 94 85 e0 fb ff ff 88 16 90 89 d2 90 46 ff 4d e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}