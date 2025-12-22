
rule Trojan_Win64_EggStremeLoader_I_dha{
	meta:
		description = "Trojan:Win64/EggStremeLoader.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 48 9a e5 [0-06] b9 b6 6e 1a [0-06] 5c 59 c7 66 [0-06] 08 c2 df 19 [0-06] 37 ce 4a 40 [0-06] 75 fc 5e e3 [0-06] 09 6e f1 61 [0-06] fd ca 68 67 } //1
		$a_00_1 = {8b 44 8f fc 2d 47 86 c8 61 89 04 8f 48 ff c1 48 83 f9 1a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}