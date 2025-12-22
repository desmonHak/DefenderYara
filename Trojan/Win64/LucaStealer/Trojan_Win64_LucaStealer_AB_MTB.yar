
rule Trojan_Win64_LucaStealer_AB_MTB{
	meta:
		description = "Trojan:Win64/LucaStealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 83 c0 40 48 89 c1 48 81 e1 00 ff ff ff 0f b6 d0 48 09 ca 48 8d ?? ?? ?? 48 89 f1 e8 } //1
		$a_00_1 = {6c 6f 67 73 63 78 5c 63 72 65 64 69 74 63 61 72 64 73 } //1 logscx\creditcards
		$a_00_2 = {6c 6f 67 73 63 78 5c 54 65 6c 65 67 72 61 6d } //1 logscx\Telegram
		$a_00_3 = {6c 6f 67 73 63 78 5c 73 65 6e 73 66 69 6c 65 73 2e 7a 69 70 } //1 logscx\sensfiles.zip
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}