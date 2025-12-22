
rule Trojan_Win64_Agent_ARR_MTB{
	meta:
		description = "Trojan:Win64/Agent.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 45 49 76 4b 41 6b 48 2e 66 75 6e 63 31 2e 31 } //15 main.EIvKAkH.func1.1
		$a_01_1 = {6d 61 69 6e 2e 54 58 70 45 46 66 42 72 2e 66 75 6e 63 31 2e 67 6f 77 72 61 70 31 } //10 main.TXpEFfBr.func1.gowrap1
		$a_03_2 = {48 89 44 24 30 48 8b 59 ?? 48 8b 11 48 c1 e0 ?? 48 8b 0c 02 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_03_2  & 1)*5) >=30
 
}