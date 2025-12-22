
rule Trojan_Win32_Zusy_NZS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 b4 8b 45 e8 83 e0 23 8a 4d b4 32 c8 88 4d b4 8b 45 e0 8a 4d b4 0a 4c 05 ?? 88 4d b4 8b 45 ?? 40 89 45 e0 8b 45 fc 03 45 ?? 8a 4d b4 88 08 83 7d e0 10 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}