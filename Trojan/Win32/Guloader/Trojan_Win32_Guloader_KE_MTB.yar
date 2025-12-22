
rule Trojan_Win32_Guloader_KE_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {74 72 61 6e 73 6f 72 62 69 74 61 6c 20 72 61 64 69 6f 65 72 73 20 67 65 6e 65 72 69 63 61 6c 6c 79 } //1 transorbital radioers generically
		$a_81_1 = {69 62 72 75 67 74 61 67 65 20 70 69 6c 73 6e 65 72 6e 65 73 20 6d 79 63 6f 73 74 65 72 6f 6c } //1 ibrugtage pilsnernes mycosterol
		$a_81_2 = {6d 75 73 69 6b 70 64 61 67 6f 67 65 72 6e 65 2e 65 78 65 } //1 musikpdagogerne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}