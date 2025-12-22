
rule Trojan_Win64_DonutLoader_CD_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? 0f b6 8c 0c ?? ?? ?? ?? 31 c8 88 c2 48 8b 84 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 48 03 4c 24 ?? 88 14 08 48 8b 44 24 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}