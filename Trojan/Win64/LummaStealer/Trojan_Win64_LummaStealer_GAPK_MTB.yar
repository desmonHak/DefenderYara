
rule Trojan_Win64_LummaStealer_GAPK_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GAPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {d0 1b 61 c4 8a 38 b3 12 d5 24 d5 40 eb a8 2a 88 cc 0d f0 01 9e 5d } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}