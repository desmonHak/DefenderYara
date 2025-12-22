
rule Trojan_Win64_CoinMiner_MKA_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 03 00 00 "
		
	strings :
		$a_01_0 = {60 00 00 68 2e 72 73 72 63 00 00 00 98 91 02 00 00 } //25
		$a_03_1 = {01 00 09 04 00 00 58 02 00 00 68 ?? ?? 01 e9 13 00 00 } //10
		$a_03_2 = {40 00 00 40 2e 64 61 74 61 00 00 00 ?? d0 5a 00 00 40 01 } //5
	condition:
		((#a_01_0  & 1)*25+(#a_03_1  & 1)*10+(#a_03_2  & 1)*5) >=40
 
}