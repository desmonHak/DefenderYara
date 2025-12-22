
rule Trojan_Win64_Mikey_NP_MTB{
	meta:
		description = "Trojan:Win64/Mikey.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c7 48 63 cf 48 8d 55 ?? 48 03 d1 0f b6 0a 41 88 08 44 88 0a 41 0f b6 10 49 03 d1 0f b6 ca 0f b6 54 0d ?? 41 30 12 49 ff c2 49 83 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}