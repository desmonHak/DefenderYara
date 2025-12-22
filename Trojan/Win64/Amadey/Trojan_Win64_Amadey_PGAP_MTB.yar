
rule Trojan_Win64_Amadey_PGAP_MTB{
	meta:
		description = "Trojan:Win64/Amadey.PGAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b c1 4d 8d 5b 01 4d 0f 47 c7 4d 8d 52 01 33 d2 41 ff c1 41 f7 f6 42 0f b6 04 02 41 32 42 ff 41 88 43 ff 41 81 f9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Amadey_PGAP_MTB_2{
	meta:
		description = "Trojan:Win64/Amadey.PGAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 cf 48 8d 55 ?? 48 03 d1 0f b6 0a 41 88 09 44 88 12 41 0f b6 11 49 03 d2 0f b6 ca 0f b6 54 0d ?? 41 30 10 49 ff c0 49 83 eb ?? 75 9d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}