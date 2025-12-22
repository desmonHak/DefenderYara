
rule Trojan_Win64_ValleyRAT_NW_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 54 24 ?? 0f b6 04 02 33 c1 48 63 4c 24 ?? 48 8b 54 24 ?? 48 ff ca 48 6b d2 ?? 48 03 4c 24 ?? 88 04 11 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}