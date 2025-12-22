
rule Trojan_Win32_Zusy_MK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? ?? 00 00 40 0d 00 00 } //10
		$a_03_1 = {40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 ?? ?? 00 00 02 00 00 } //10
		$a_01_2 = {20 20 20 00 20 20 20 20 00 30 0d 00 00 10 00 00 00 38 06 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}