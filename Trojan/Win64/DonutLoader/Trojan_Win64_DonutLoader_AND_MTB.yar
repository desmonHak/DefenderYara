
rule Trojan_Win64_DonutLoader_AND_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.AND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 ff 15 ?? ?? ?? ?? 48 8b f0 48 8d 0d ?? db 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 ?? db 01 00 48 8b c8 ff 15 ?? ?? ?? ?? 4c 8b f8 48 8d 0d ?? db 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 ?? db 01 00 48 8b c8 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}