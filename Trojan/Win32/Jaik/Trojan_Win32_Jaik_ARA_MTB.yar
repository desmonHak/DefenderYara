
rule Trojan_Win32_Jaik_ARA_MTB{
	meta:
		description = "Trojan:Win32/Jaik.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 c2 02 00 91 ?? ?? 40 00 41 3b ce 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Jaik_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Jaik.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 99 58 16 43 00 32 da 88 99 58 16 43 00 41 81 f9 db db 01 00 72 e9 33 c9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}