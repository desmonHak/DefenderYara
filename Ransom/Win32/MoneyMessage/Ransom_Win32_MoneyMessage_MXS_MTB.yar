
rule Ransom_Win32_MoneyMessage_MXS_MTB{
	meta:
		description = "Ransom:Win32/MoneyMessage.MXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {34 64 33 d2 88 85 ?? fe ff ff 8a 85 ?? fe ff ff 0f 1f 44 00 00 8a 84 15 ?? fe ff ff 8b 8d ?? fe ff ff 02 ca 32 c8 88 8c 15 ?? fe ff ff 42 83 fa 18 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}