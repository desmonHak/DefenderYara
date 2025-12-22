
rule Trojan_Win64_Zusy_PST_MTB{
	meta:
		description = "Trojan:Win64/Zusy.PST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff c3 f7 e9 03 d1 c1 fa 08 8b c2 c1 e8 1f 03 d0 b8 67 66 66 66 69 d2 c8 01 00 00 2b ca 41 f7 eb 80 c1 36 43 30 0c 08 c1 fa 02 41 8b cb 8b c2 c1 e8 1f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}