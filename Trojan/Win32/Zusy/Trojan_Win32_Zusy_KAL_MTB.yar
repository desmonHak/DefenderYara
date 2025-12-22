
rule Trojan_Win32_Zusy_KAL_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b f0 8b 45 e0 31 30 83 c3 04 83 45 e0 04 3b 5d dc } //20
		$a_01_1 = {8b 45 e0 01 18 8b 7d d4 03 7d a8 03 fb 03 fe c7 45 bc } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}