
rule Trojan_BAT_DCrat_BM_AMTB{
	meta:
		description = "Trojan:BAT/DCrat.BM!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {5c 44 63 52 61 74 } //\DcRat  1
		$a_80_1 = {4d 65 73 73 61 67 65 50 61 63 6b 4c 69 62 2e 4d 65 73 73 61 67 65 50 61 63 6b } //MessagePackLib.MessagePack  1
		$a_80_2 = {31 2e 30 2e 37 } //1.0.7  1
		$a_80_3 = {45 6e 63 6f 64 65 32 42 79 74 65 73 } //Encode2Bytes  1
		$a_80_4 = {53 65 74 41 73 42 6f 6f 6c 65 61 6e } //SetAsBoolean  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}