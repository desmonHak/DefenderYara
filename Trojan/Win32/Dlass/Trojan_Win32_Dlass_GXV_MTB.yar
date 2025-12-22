
rule Trojan_Win32_Dlass_GXV_MTB{
	meta:
		description = "Trojan:Win32/Dlass.GXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 d4 5e 6f 00 e5 cc 6b 00 00 } //10
		$a_03_1 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 1d ?? ?? ?? ?? a3 ?? ?? ?? ?? 0a 00 85 c0 c0 46 1e 36 6c 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}