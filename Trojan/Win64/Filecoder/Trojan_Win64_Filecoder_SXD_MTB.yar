
rule Trojan_Win64_Filecoder_SXD_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 ff cc 4c 89 64 24 ?? 4c 8b 6c 24 ?? 4c 89 e0 48 c1 e0 05 49 8b 7c 05 00 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 39 cf 0f 84 } //3
		$a_03_1 = {4c 89 e9 48 c1 e1 ?? 4c 89 24 08 48 89 5c 08 08 48 8d 94 24 ?? ?? ?? ?? f3 0f 6f 02 f3 0f 7f 44 08 10 49 ff c5 4c 89 6c 24 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}