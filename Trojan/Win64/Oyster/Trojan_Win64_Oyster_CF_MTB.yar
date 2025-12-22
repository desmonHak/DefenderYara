
rule Trojan_Win64_Oyster_CF_MTB{
	meta:
		description = "Trojan:Win64/Oyster.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 19 31 41 ?? 48 83 c1 08 48 39 d1 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}