
rule Trojan_Win64_Lazy_AHJ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 50 48 8b 8c 24 a0 05 00 00 33 d2 0f b6 3c 11 40 88 3c 10 48 ff c2 40 84 ff 75 } //20
		$a_01_1 = {72 75 6e 20 73 68 65 6c 6c 63 6f 64 65 } //5 run shellcode
		$a_01_2 = {62 65 67 69 6e 20 6c 6f 61 64 20 73 68 65 6c 6c 63 6f 64 65 } //5 begin load shellcode
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=30
 
}
rule Trojan_Win64_Lazy_AHJ_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_03_0 = {42 0f be 14 07 49 ff c0 69 cb ?? ?? ?? ?? 2b d1 81 e2 ?? ?? ?? ?? 03 da 4c 3b c0 72 } //40
		$a_01_1 = {63 20 22 66 6f 72 20 2f 66 20 22 74 6f 6b 65 6e 73 3d 32 20 64 65 6c 69 6d 73 3d 3a 20 22 20 25 69 20 69 6e 20 28 27 73 63 20 71 75 65 72 79 65 78 20 53 63 68 65 64 75 6c 65 } //30 c "for /f "tokens=2 delims=: " %i in ('sc queryex Schedule
		$a_01_2 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 64 72 61 67 6f 6e 77 65 6c 6c 5c 4a 61 76 61 5c 6a 61 76 61 70 61 74 68 } //20 ProgramData\dragonwell\Java\javapath
		$a_01_3 = {66 69 6e 64 73 74 72 20 50 49 44 27 29 20 64 6f 20 74 61 73 6b 6b 69 6c 6c 20 2f 50 49 44 20 25 69 20 2f 46 } //10 findstr PID') do taskkill /PID %i /F
	condition:
		((#a_03_0  & 1)*40+(#a_01_1  & 1)*30+(#a_01_2  & 1)*20+(#a_01_3  & 1)*10) >=100
 
}