
rule Trojan_Win64_Lazy_AX_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 d0 21 d0 f7 d2 89 d3 31 cb 21 d3 21 d1 09 c1 89 d8 f7 d0 89 ca f7 d2 89 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Lazy_AX_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 44 0f b7 84 24 10 02 00 00 48 8b 94 24 08 02 00 00 48 8b 8c 24 c8 00 00 00 ff 15 ?? ?? ?? ?? 48 89 84 24 d0 00 00 00 48 83 bc 24 d0 00 00 00 00 75 } //1
		$a_81_1 = {70 61 79 6c 6f 61 64 2e 62 69 6e } //1 payload.bin
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}