
rule Trojan_Win32_Androm_BAG_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fa 03 fb 03 f8 c7 45 ?? 39 19 00 00 6a 00 e8 ?? ?? ?? ?? 03 7d a8 81 ef 39 19 00 00 2b f8 6a 00 e8 [0-1f] 03 f8 31 3e 83 c3 04 83 c6 04 3b 5d cc 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}