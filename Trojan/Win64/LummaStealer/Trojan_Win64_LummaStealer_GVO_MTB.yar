
rule Trojan_Win64_LummaStealer_GVO_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVO!MTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3b 4e 08 73 5e 44 8b c1 42 0f b6 44 06 10 8b d1 0f b6 54 13 10 2b d0 44 0f b6 c2 3b 4f 08 73 43 8b d1 41 33 c0 88 44 17 10 ff c1 3b e9 7f d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}