
rule Trojan_Win32_Fragtor_LMC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.LMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e3 00 c6 45 f2 34 c6 45 f3 00 c6 45 d4 25 c6 45 d5 73 c6 45 d6 5c c6 45 d7 25 c6 45 d8 63 c6 45 d9 25 c6 45 da 63 c6 45 db 25 c6 45 dc 63 c6 45 dd 25 c6 45 de 63 c6 45 df 00 } //30
	condition:
		((#a_01_0  & 1)*30) >=30
 
}