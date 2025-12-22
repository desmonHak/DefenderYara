
rule Trojan_Win32_Qbot_CH_MTB{
	meta:
		description = "Trojan:Win32/Qbot.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8b 55 ?? 03 95 ?? ff ff ff 0f b6 02 33 c8 8b 55 ?? 88 0a 8b } //2
		$a_03_1 = {0f b6 02 8b 4d e0 03 8d ?? ff ff ff 0f b6 11 33 c2 8b 4d e8 88 01 8b } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}