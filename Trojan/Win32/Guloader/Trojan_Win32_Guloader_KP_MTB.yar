
rule Trojan_Win32_Guloader_KP_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {6d 61 72 6d 6f 72 65 61 6c 6c 79 } //1 marmoreally
		$a_81_1 = {73 6b 61 74 74 65 64 65 70 61 72 74 65 6d 65 6e 74 65 72 6e 65 20 64 75 6d 62 66 6f 75 6e 64 69 6e 67 2e 65 78 65 } //1 skattedepartementerne dumbfounding.exe
		$a_81_2 = {63 61 63 63 61 62 69 73 20 74 65 74 72 61 6e 69 74 72 6f 61 6e 69 6c 69 6e 65 20 70 72 65 6f 70 65 6e 69 6e 67 } //1 caccabis tetranitroaniline preopening
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}