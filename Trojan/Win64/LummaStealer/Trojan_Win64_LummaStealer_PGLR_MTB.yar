
rule Trojan_Win64_LummaStealer_PGLR_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 89 d3 45 20 c3 45 30 d0 45 08 d8 20 d3 41 20 c9 41 08 d9 89 cb 30 d3 08 d1 80 f1 01 08 d9 80 f1 01 44 89 ca 20 ca 44 30 c9 08 d1 89 cb 80 f3 01 89 da 20 ca 30 d3 80 f2 01 08 ca 80 f2 01 08 da 44 30 c2 89 d3 } //5
		$a_01_1 = {83 9f f4 bd 5f d7 72 d0 3c 58 d3 5e 82 2f 5e 04 21 22 f7 55 a8 21 21 14 95 64 53 d2 33 21 3a 71 92 03 eb 11 1b 89 06 6b 83 b3 15 24 18 a3 2b 74 e5 49 50 76 14 64 b8 bc c0 3d a2 ac } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}