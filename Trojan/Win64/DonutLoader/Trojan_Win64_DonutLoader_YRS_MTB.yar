
rule Trojan_Win64_DonutLoader_YRS_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.YRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {47 0f b6 1c 10 45 03 cb 41 81 e1 ?? ?? ?? ?? 7d ?? 41 ff c9 41 81 c9 ?? ?? ?? ?? 41 ff c1 49 63 d1 42 0f b6 0c 02 } //1
		$a_03_1 = {43 0f b6 0c 10 48 03 d1 0f b6 ca 42 0f b6 14 01 32 14 2e 88 16 48 ff c6 49 83 ee ?? 75 91 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}