
rule Trojan_Win32_CoinStealer_PAGO_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.PAGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 03 32 4d ff 8b 3e 88 0c 07 40 4a 75 f0 } //2
		$a_01_1 = {58 52 50 3d } //1 XRP=
		$a_01_2 = {44 4f 54 3d } //1 DOT=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}