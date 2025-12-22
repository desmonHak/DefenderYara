
rule Trojan_Win32_Strictor_NT_MTB{
	meta:
		description = "Trojan:Win32/Strictor.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 e8 8a 14 3a 32 55 ef 88 54 18 ff 47 3b 7d f0 75 02 33 ff 43 4e 75 cf } //2
		$a_01_1 = {7e 36 bb 01 00 00 00 8b 45 fc 8a 44 18 ff 88 45 ef f6 45 ef e0 74 15 8d 45 fc } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}