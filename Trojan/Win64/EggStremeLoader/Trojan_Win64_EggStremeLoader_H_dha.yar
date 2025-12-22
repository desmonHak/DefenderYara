
rule Trojan_Win64_EggStremeLoader_H_dha{
	meta:
		description = "Trojan:Win64/EggStremeLoader.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {36 62 e6 ef [0-06] a4 f6 f6 76 [0-06] c5 43 0e c1 [0-06] bd f7 59 9f } //1
		$a_00_1 = {8b 44 8f fc 2d 47 86 c8 61 89 04 8f 48 ff c1 48 83 f9 1a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}