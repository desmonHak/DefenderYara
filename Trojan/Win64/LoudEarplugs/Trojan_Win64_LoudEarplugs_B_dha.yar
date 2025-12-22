
rule Trojan_Win64_LoudEarplugs_B_dha{
	meta:
		description = "Trojan:Win64/LoudEarplugs.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bc b4 e7 b1 e6 b7 b4 e7 bd b1 b4 b7 b3 b2 e0 e4 b6 e0 bc e7 e4 e7 bc b7 b6 bc b3 b6 b4 bd e0 b2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_LoudEarplugs_B_dha_2{
	meta:
		description = "Trojan:Win64/LoudEarplugs.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_43_0 = {81 50 79 c7 85 90 01 04 4c 52 28 e9 c7 85 90 01 04 ab b7 ed 09 c7 85 90 01 04 bf ac 98 86 c7 85 90 01 04 65 a0 e8 70 c7 85 90 01 04 ef e0 68 f2 c7 85 90 01 04 cc e1 6f 11 c7 85 90 01 04 b0 5c 15 7a c7 85 90 01 04 49 1b ee 19 c7 85 90 01 04 b9 f4 eb 2a c7 85 90 01 04 e7 fa fd a3 c7 85 90 01 04 6c 48 89 3c c7 85 90 01 04 d0 35 42 4d c7 85 90 01 04 3f 19 6a df c7 85 90 01 04 d4 2e 99 5b c7 85 90 01 04 8c fb ce 59 90 00 00 } //1
	condition:
		((#a_43_0  & 1)*1) >=1
 
}