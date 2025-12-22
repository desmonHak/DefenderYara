
rule Trojan_Win64_ShellcodeLoader_AN_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 63 6f 64 65 4c 6f 61 64 65 72 } //1 ShellcodeLoader
		$a_01_1 = {6c 61 74 65 73 74 75 6d 61 6e 67 2e 6e 65 74 6c 69 66 79 2e 61 70 70 2f 73 68 65 6c 6c 63 6f 64 65 2e 62 69 6e } //1 latestumang.netlify.app/shellcode.bin
		$a_01_2 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}