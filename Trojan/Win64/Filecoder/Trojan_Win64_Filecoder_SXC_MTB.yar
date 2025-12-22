
rule Trojan_Win64_Filecoder_SXC_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 95 80 0b 00 00 48 8d 85 58 15 00 00 48 89 c1 e8 ?? ?? ?? ?? 89 c2 8b 85 4c 18 00 00 48 98 88 94 05 ?? ?? ?? ?? 83 85 4c 18 00 00 } //3
		$a_01_1 = {0f b6 94 05 60 15 00 00 44 8b 85 48 18 00 00 48 8b 85 10 18 00 00 4c 01 c0 31 ca 88 10 83 85 48 18 00 00 01 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}