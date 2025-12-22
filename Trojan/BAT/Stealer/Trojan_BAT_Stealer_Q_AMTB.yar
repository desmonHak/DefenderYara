
rule Trojan_BAT_Stealer_Q_AMTB{
	meta:
		description = "Trojan:BAT/Stealer.Q!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {73 74 72 6f 6e 67 64 77 6e 2e 63 6f 6d } //strongdwn.com  3
		$a_02_1 = {43 00 72 00 79 00 73 00 74 00 61 00 6c 00 [0-02] 50 00 44 00 46 00 2e 00 65 00 78 00 65 00 } //2
	condition:
		((#a_80_0  & 1)*3+(#a_02_1  & 1)*2) >=5
 
}