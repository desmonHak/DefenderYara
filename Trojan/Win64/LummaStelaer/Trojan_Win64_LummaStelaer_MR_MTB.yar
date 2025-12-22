
rule Trojan_Win64_LummaStelaer_MR_MTB{
	meta:
		description = "Trojan:Win64/LummaStelaer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 ?? ?? ?? c0 05 00 00 02 } //5
		$a_03_1 = {40 00 00 e0 2e 72 73 72 63 ?? ?? ?? c0 02 ?? ?? ?? b0 05 00 00 02 ?? ?? ?? b0 05 } //5
		$a_03_2 = {20 20 20 00 20 20 20 20 00 a0 05 00 00 10 ?? ?? ?? a0 05 00 00 10 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}