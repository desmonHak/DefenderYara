
rule Trojan_Win64_Zusy_MK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 6c 41 48 67 41 5a 51 41 69 41 43 41 41 61 41 42 30 41 48 51 41 63 41 42 7a 41 44 6f 41 4c 77 41 76 41 47 63 41 61 51 42 30 41 47 67 41 64 51 42 69 41 43 34 41 59 77 42 76 41 47 30 41 4c 77 42 30 41 48 4d 41 5a 77 } //20 BlAHgAZQAiACAAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwB0AHMAZw
		$a_03_1 = {48 89 54 24 50 48 c7 44 24 68 0f 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 54 24 60 48 c7 44 24 78 f8 03 } //5
		$a_03_2 = {48 8b 6d 00 48 c7 44 24 48 0a 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 54 24 40 48 c7 44 24 58 0c } //5
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=25
 
}