
rule Trojan_Win32_GuLoader_RDF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {75 64 76 69 72 6b 65 64 65 73 } //1 udvirkedes
		$a_81_1 = {73 74 69 6c 6c 65 6c 73 6e 69 6e 67 73 70 72 76 65 6e 20 6c 6f 76 72 65 67 65 6c 65 6e 20 68 61 61 6e 64 76 72 6b 73 72 61 61 64 65 74 73 } //1 stillelsningsprven lovregelen haandvrksraadets
		$a_81_2 = {69 6e 73 65 6b 74 65 72 6e 65 73 20 63 61 70 72 69 70 65 64 65 } //1 insekternes capripede
		$a_81_3 = {72 65 6f 78 69 64 69 7a 65 20 75 72 6f 76 61 72 73 6c 69 6e 67 73 2e 65 78 65 } //1 reoxidize urovarslings.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}