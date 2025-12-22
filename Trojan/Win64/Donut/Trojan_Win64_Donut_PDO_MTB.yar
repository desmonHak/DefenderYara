
rule Trojan_Win64_Donut_PDO_MTB{
	meta:
		description = "Trojan:Win64/Donut.PDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 41 f7 f9 41 31 f2 44 01 ee 46 88 14 1b 48 63 d2 45 32 14 10 46 88 14 1b 49 83 c3 01 49 39 fb 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}