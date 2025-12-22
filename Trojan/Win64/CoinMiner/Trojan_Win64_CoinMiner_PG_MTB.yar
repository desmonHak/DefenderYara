
rule Trojan_Win64_CoinMiner_PG_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 78 02 48 b9 b2 18 bf 10 be 21 b6 13 48 89 08 48 8d 35 48 86 10 00 b9 10 7f 00 00 f3 48 a5 48 89 84 24 60 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}