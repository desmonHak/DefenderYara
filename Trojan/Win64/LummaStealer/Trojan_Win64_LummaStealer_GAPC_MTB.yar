
rule Trojan_Win64_LummaStealer_GAPC_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GAPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 c8 51 1b 9d 90 5f 9f 66 ae 45 57 c8 9c 68 a0 d1 d0 1c f5 df 7d b2 4d 82 fe f5 15 5c e8 0c 31 0d 4c 76 a4 6b 8e 6f 45 75 36 63 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}