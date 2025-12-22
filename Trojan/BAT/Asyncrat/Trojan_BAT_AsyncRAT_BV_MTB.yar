
rule Trojan_BAT_AsyncRAT_BV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e f5 00 00 04 20 80 75 4e f6 65 20 dd 28 e6 78 59 20 a3 61 cb ?? 61 7d ff 00 00 04 20 3a 00 00 00 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}