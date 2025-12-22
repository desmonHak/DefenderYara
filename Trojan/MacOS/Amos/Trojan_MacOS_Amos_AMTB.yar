
rule Trojan_MacOS_Amos_AMTB{
	meta:
		description = "Trojan:MacOS/Amos!AMTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {5f 5f 5a 4e 34 6d 6c 63 67 34 70 72 6e 67 45 6a } //__ZN4mlcg4prngEj  1
		$a_80_1 = {4e 34 6d 6c 63 67 34 70 72 6e 67 45 6a } //N4mlcg4prngEj  1
		$a_80_2 = {40 5f 5f 5a 4e 34 6d 6c 63 67 34 70 72 6e 67 45 6a } //@__ZN4mlcg4prngEj  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}