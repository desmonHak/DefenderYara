
rule Trojan_Win64_LummaStealer_GAPU_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GAPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {a7 01 e9 4e 5d ef 01 cc 50 3c cc 1e b8 f8 cb bd 46 8f d2 52 49 af d9 ac e7 cb d4 82 a3 47 a6 89 31 6e 99 8a } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}