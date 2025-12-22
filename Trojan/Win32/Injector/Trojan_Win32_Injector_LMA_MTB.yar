
rule Trojan_Win32_Injector_LMA_MTB{
	meta:
		description = "Trojan:Win32/Injector.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 6b c0 33 8b 55 ?? d1 fa 09 c2 8b 45 ?? 31 d0 89 45 ?? 8b 45 ?? 83 e0 0f 83 f8 0a 0f 94 c0 84 c0 } //20
		$a_03_1 = {8b 45 fc 83 e0 01 85 c0 75 ?? 8b 45 f8 33 45 fc 89 45 f8 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}