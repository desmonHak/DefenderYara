
rule Trojan_Win64_EggStremeLoader_L_dha{
	meta:
		description = "Trojan:Win64/EggStremeLoader.L!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_40_0 = {55 c0 c8 04 0f b6 c8 6b c2 0d 83 c0 1d 01 } //1
		$a_69_1 = {06 } //8192
	condition:
		((#a_40_0  & 1)*1+(#a_69_1  & 1)*8192) >=2
 
}