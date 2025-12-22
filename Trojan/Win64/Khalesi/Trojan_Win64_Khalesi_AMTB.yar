
rule Trojan_Win64_Khalesi_AMTB{
	meta:
		description = "Trojan:Win64/Khalesi!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {41 4e 54 49 5f 44 49 53 41 53 53 4d } //ANTI_DISASSM  1
		$a_80_1 = {43 4f 44 45 5f 49 4e 4a 45 43 54 49 4f 4e 53 } //CODE_INJECTIONS  1
		$a_80_2 = {54 49 4d 49 4e 47 5f 41 54 54 41 43 4b 53 } //TIMING_ATTACKS  1
		$a_80_3 = {61 6c 2d 6b 68 61 73 65 72 2e 70 64 62 } //al-khaser.pdb  1
		$a_80_4 = {49 6e 6a 65 63 74 65 64 20 6c 69 62 72 61 72 79 3a 20 25 53 } //Injected library: %S  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}