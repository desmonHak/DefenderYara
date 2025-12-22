
rule Trojan_Win64_Khalesi_PGKH_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.PGKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f 6b 36 6d 34 73 34 2e 62 61 74 } //2 https://files.catbox.moe/k6m4s4.bat
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f 6c 33 77 68 6a 62 2e 77 61 76 } //2 https://files.catbox.moe/l3whjb.wav
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f 6c 67 32 6a 69 77 2e 62 61 74 } //2 https://files.catbox.moe/lg2jiw.bat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}