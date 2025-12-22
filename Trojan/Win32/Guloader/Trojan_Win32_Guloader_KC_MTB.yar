
rule Trojan_Win32_Guloader_KC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {6d 6f 62 69 6c 69 73 6e 77 72 20 62 69 6e 67 6f 65 72 73 } //1 mobilisnwr bingoers
		$a_81_1 = {6e 61 61 6c 65 6e 65 20 66 6f 72 62 65 68 61 6e 64 6c 65 64 65 2e 65 78 65 } //1 naalene forbehandlede.exe
		$a_81_2 = {67 61 77 6b 73 20 64 61 74 61 74 72 61 6e 73 70 6f 72 74 65 72 } //1 gawks datatransporter
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}