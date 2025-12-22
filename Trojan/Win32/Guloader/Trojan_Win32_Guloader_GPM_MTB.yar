
rule Trojan_Win32_Guloader_GPM_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 6b 6f 76 67 61 6e 67 73 6d 6e 64 65 6e 65 2e 66 72 6b } //1 Skovgangsmndene.frk
		$a_81_1 = {70 68 61 73 65 6c 65 73 73 2e 70 61 74 } //1 phaseless.pat
		$a_81_2 = {74 6c 6c 65 6c 69 67 65 73 2e 6b 72 69 } //1 tlleliges.kri
		$a_81_3 = {50 6f 6c 69 74 69 76 65 64 74 67 74 65 72 73 } //1 Politivedtgters
		$a_81_4 = {52 65 6b 6c 61 6d 65 62 75 72 65 61 75 65 72 6e 65 73 } //1 Reklamebureauernes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}