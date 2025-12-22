
rule Trojan_Win64_BadJoke_ARR_MTB{
	meta:
		description = "Trojan:Win64/BadJoke.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {29 ca 8d 0c 92 c1 e1 ?? 29 c8 89 c2 0f 84 } //15
		$a_03_1 = {45 89 f1 41 b8 ?? ?? ?? ?? 48 89 f1 89 6c 24 48 ba } //10
		$a_81_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 20 2d 2d 68 65 61 64 6c 65 73 73 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 77 6c 72 6d 64 72 2e 65 78 65 20 2d 73 20 36 30 30 30 30 20 2d 66 20 32 20 2d 74 20 22 25 73 22 20 2d 6d 20 22 25 73 22 } //5 C:\Windows\System32\conhost.exe --headless C:\Windows\System32\wlrmdr.exe -s 60000 -f 2 -t "%s" -m "%s"
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10+(#a_81_2  & 1)*5) >=30
 
}