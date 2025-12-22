
rule Trojan_Win32_Korplug_GZF_MTB{
	meta:
		description = "Trojan:Win32/Korplug.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 c9 8a 5c 0c ?? 00 da 0f b6 f2 8a 7c 34 ?? 88 7c 0c ?? 88 5c 34 ?? 02 5c 0c ?? 0f b6 f3 8a 5c 34 ?? 8b 74 24 ?? 32 1c 06 8b 74 24 ?? 88 1c 06 40 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}