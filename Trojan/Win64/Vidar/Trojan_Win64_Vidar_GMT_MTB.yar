
rule Trojan_Win64_Vidar_GMT_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 38 1d f0 66 0f 6d fb 41 88 0c 08 48 ff c1 66 0f 38 1d f0 66 0f 6d fb 48 83 f9 72 ?? ?? 48 31 c9 ?? 48 ff c2 66 0f 38 1d f0 66 0f 6d fb 48 81 fa } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}