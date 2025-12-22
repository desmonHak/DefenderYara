
rule Trojan_Win64_Redcap_GZF_MTB{
	meta:
		description = "Trojan:Win64/Redcap.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? 48 8b 54 24 ?? 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 ?? 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01 0f b6 05 ?? ?? ?? ?? 48 8b 4c 24 ?? 48 8b 54 24 40 48 03 d1 48 8b ca 0f b6 09 03 c8 8b c1 48 8b 4c 24 ?? 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}