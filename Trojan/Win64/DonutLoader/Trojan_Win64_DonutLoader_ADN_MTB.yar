
rule Trojan_Win64_DonutLoader_ADN_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 33 c9 e8 ?? ?? ?? ?? 48 8b 55 68 8b f8 48 83 fa 0f 76 36 48 8b 4d 50 48 ff c2 48 81 fa ?? ?? ?? ?? 72 1b 4c 8b 41 f8 49 2b c8 48 83 e9 08 48 83 f9 1f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}