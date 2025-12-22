
rule Trojan_Win64_Injuke_MK_MTB{
	meta:
		description = "Trojan:Win64/Injuke.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10 8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 0f b6 04 10 83 f0 a5 } //20
		$a_03_1 = {8b 55 1c 48 8b 45 10 48 01 d0 44 0f b6 00 0f b6 0d ?? ?? ?? ?? 8b 55 1c 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}