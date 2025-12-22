
rule Trojan_BAT_PureCrypter_PS_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 08 06 6f ?? ?? ?? 0a 08 07 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d dd ?? ?? ?? 00 08 39 ?? ?? ?? 00 08 6f ?? ?? ?? 0a dc } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {47 65 74 46 61 6b 65 50 61 79 6c 6f 61 64 } //1 GetFakePayload
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}