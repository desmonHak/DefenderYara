
rule Trojan_Win64_LummaStealer_GAPJ_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GAPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {ea df 46 8f be a9 bd b9 9b f2 aa 20 1a 18 4d 38 ee } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}