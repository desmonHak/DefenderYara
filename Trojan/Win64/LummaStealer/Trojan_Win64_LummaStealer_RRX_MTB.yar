
rule Trojan_Win64_LummaStealer_RRX_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.RRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 e7 3f 41 81 ee f7 92 f7 57 41 f7 d6 41 81 e6 a4 d8 b6 7b 41 ff ce 41 f7 d6 41 81 ee 26 7c a4 bc 44 01 f3 41 31 c6 89 d8 } //5
		$a_01_1 = {81 c2 10 18 75 3b 81 c6 3d 9d 31 9a 89 f0 52 ba e0 8e e5 45 29 d6 5a 81 ee 2e 25 76 6a 01 d6 81 c6 2e 25 76 6a 81 c6 e0 8e e5 45 } //5
		$a_01_2 = {81 c2 96 ec 66 39 81 ea 00 00 ff 4f 31 d2 be 80 94 67 3d 81 f6 be 69 89 3a 29 f2 01 c6 31 d6 29 da 81 c2 3e fd ee 07 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=5
 
}