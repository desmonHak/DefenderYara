
rule Trojan_Win64_ShellcodeRunner_NPC_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b8 ca 0f af c1 41 39 c2 73 } //2
		$a_01_1 = {48 b8 01 ed 83 7c 24 10 03 0f } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}