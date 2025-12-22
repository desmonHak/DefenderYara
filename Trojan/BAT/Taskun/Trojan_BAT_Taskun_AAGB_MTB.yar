
rule Trojan_BAT_Taskun_AAGB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AAGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 1e 6a 0d 0e 05 6a 08 61 09 5b 13 04 11 04 } //5
		$a_01_1 = {11 0e 8e 69 17 58 11 0f 8e 69 58 17 58 06 8e 69 58 8d } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}