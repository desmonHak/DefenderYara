
rule Trojan_MacOS_Amos_ED_MTB{
	meta:
		description = "Trojan:MacOS/Amos.ED!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 8b 7e 08 48 85 ff 0f 84 69 02 00 00 4d 01 fd 31 db 45 31 e4 48 85 ff 0f 84 41 02 00 00 90 } //1
		$a_01_1 = {55 48 89 e5 53 50 48 89 fb e8 1e 08 00 00 48 89 df 48 83 c4 08 5b 5d e9 1c 08 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}