
rule Trojan_Win64_ShellcodeLoader_AHB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 00 48 8b 85 ?? ?? ?? 00 0f b7 08 81 f1 ?? ?? 00 00 0f b6 40 02 35 ?? 00 00 00 66 09 c8 } //30
		$a_01_1 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 66 69 6e 64 20 27 6d 6f 76 20 72 63 78 2c 20 72 38 27 20 70 61 74 74 65 72 6e } //20 [-] Failed to find 'mov rcx, r8' pattern
		$a_01_2 = {5b 2b 5d 20 53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 73 79 73 63 61 6c 6c } //10 [+] Searching for syscall
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}