
rule Trojan_Win32_Zbot_NB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 86 00 00 00 8b 55 0c 03 55 f4 0f b6 02 89 45 f8 c7 45 fc 86 00 00 00 8b 4d 08 03 4d f4 8a 55 f8 88 11 c7 45 fc 86 00 00 00 eb c1 } //2
		$a_01_1 = {c7 45 ec 03 00 00 00 8b 4d 08 8b 51 04 83 ea 08 d1 ea 89 55 f4 8b 45 08 83 c0 08 89 45 f0 c7 45 fc 00 00 00 00 eb 09 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}