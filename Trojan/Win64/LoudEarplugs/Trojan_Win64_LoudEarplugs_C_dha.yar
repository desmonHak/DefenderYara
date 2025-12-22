
rule Trojan_Win64_LoudEarplugs_C_dha{
	meta:
		description = "Trojan:Win64/LoudEarplugs.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 46 44 43 35 41 46 34 2d 2a 26 40 32 33 33 44 3c 3e 28 26 2d 34 33 32 63 2e 3f 5f 2b 2d 41 42 24 7e 38 37 2d 33 45 43 42 4e 45 42 58 52 54 26 36 35 46 45 4b 2b 2a 23 45 32 4e 4d 3a 35 30 21 7e 37 36 2d 3f 2a } //1 EFDC5AF4-*&@233D<>(&-432c.?_+-AB$~87-3ECBNEBXRT&65FEK+*#E2NM:50!~76-?*
		$a_42_1 = {00 30 04 3e e8 90 01 04 8b c8 33 d2 8d 43 01 46 f7 f1 8b da 3b 75 90 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_42_1  & 1)*1) >=1
 
}