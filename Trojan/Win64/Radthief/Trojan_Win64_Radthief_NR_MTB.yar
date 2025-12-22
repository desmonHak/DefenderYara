
rule Trojan_Win64_Radthief_NR_MTB{
	meta:
		description = "Trojan:Win64/Radthief.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 39 41 8b 40 ?? 24 01 74 2c 49 83 78 ?? 00 74 25 48 c7 44 24 08 00 00 00 00 48 8b 44 24 08 49 89 40 ?? 8b 05 ba 4d 1e 00 d1 e8 a8 01 74 0c } //2
		$a_03_1 = {ba 68 1e 00 48 8b 01 ff 50 ?? 48 8b d7 48 8b c8 4c 8b 00 4d 8b 48 ?? 44 8b c3 48 8b 5c 24 30 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}