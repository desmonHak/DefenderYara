
rule Trojan_Win64_LummaStealer_ETL_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 84 24 e0 01 00 00 65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 40 20 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}