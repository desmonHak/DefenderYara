
rule Trojan_Win64_Oyster_ZF_MTB{
	meta:
		description = "Trojan:Win64/Oyster.ZF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b8 41 39 ff 73 13 48 8b 5c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}