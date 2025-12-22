
rule Trojan_Win64_DelShad_MR_MTB{
	meta:
		description = "Trojan:Win64/DelShad.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 40 2e 72 73 72 63 00 00 00 58 f7 00 00 00 a0 44 00 00 f8 00 00 00 bc 42 } //5
		$a_03_1 = {40 00 00 40 2e 69 64 61 74 61 ?? ?? ?? 10 ?? ?? ?? a0 45 00 00 02 00 00 00 b4 43 } //5
		$a_01_2 = {40 00 00 40 20 20 20 20 20 20 20 20 38 3c 41 00 00 20 03 00 00 28 41 00 00 7a 01 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}