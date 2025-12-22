
rule Trojan_Win64_CobaltStrike_SRA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SRA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 54 d5 00 4c 01 f2 4f 8d 04 40 49 83 c0 06 48 83 f1 03 45 31 d2 45 31 db 48 be 93 2d 59 57 18 77 87 0e 49 39 f1 41 0f 93 c2 4e 8d 14 95 04 00 00 00 41 0f 95 c3 4e 8d 1c 9d 07 00 00 00 31 f6 4d 39 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}