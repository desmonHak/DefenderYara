
rule Trojan_Win32_Rhadamanthus_MR_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthus.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 40 20 20 20 20 20 20 20 20 14 c9 03 00 00 e0 05 00 00 36 01 } //5
		$a_03_1 = {40 00 00 c0 20 20 20 20 20 20 20 20 68 40 ?? ?? ?? b0 09 00 00 38 ?? ?? ?? 36 04 } //5
		$a_03_2 = {40 00 00 40 2e 69 64 61 74 61 ?? ?? ?? 10 ?? ?? ?? ?? 0a 00 00 02 ?? ?? ?? 6e 04 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}