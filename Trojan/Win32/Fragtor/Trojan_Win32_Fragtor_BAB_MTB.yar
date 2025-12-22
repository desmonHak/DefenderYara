
rule Trojan_Win32_Fragtor_BAB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f0 8b 45 dc 31 30 83 c3 04 83 45 dc 04 3b 5d d8 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}