
rule Trojan_Win32_Fragtor_AHB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 6c 6a 6c 6a 64 6a 2e 6a 32 6a 33 6a 6c 53 6a 6e 6a 72 53 6a 6b 8d 85 ec fe ff ff } //20
		$a_03_1 = {8d 45 f4 50 8d 85 ec ee ff ff 68 ?? ?? ?? ?? 50 ff 55 f8 85 c0 75 } //30
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}