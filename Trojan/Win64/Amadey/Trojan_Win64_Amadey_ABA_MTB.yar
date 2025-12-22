
rule Trojan_Win64_Amadey_ABA_MTB{
	meta:
		description = "Trojan:Win64/Amadey.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 0f b6 01 41 88 04 19 44 88 11 41 0f b6 0c 19 49 03 ca 0f b6 c1 0f b6 4c 04 ?? 42 32 0c 07 41 88 08 49 ff c0 49 83 eb 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}