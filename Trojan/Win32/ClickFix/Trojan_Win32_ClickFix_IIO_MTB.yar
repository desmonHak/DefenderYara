
rule Trojan_Win32_ClickFix_IIO_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IIO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 00 4f 00 53 00 54 00 29 00 3b 00 69 00 65 00 78 00 20 00 24 00 } //1 POST);iex $
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
		$a_00_2 = {2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 .content
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_ClickFix_IIO_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.IIO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 00 6f 00 72 00 45 00 61 00 63 00 68 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 24 00 5f 00 } //1 ForEach-Object{[char]$_
		$a_00_1 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 .GetString
		$a_00_2 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_ClickFix_IIO_MTB_3{
	meta:
		description = "Trojan:Win32/ClickFix.IIO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
		$a_00_1 = {2e 00 6a 00 70 00 67 00 7c 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 3b 00 24 00 } //10 .jpg|Invoke-Expression;$
		$a_00_2 = {2e 00 6a 00 70 00 67 00 7c 00 49 00 65 00 78 00 3b 00 24 00 } //10 .jpg|Iex;$
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=11
 
}
rule Trojan_Win32_ClickFix_IIO_MTB_4{
	meta:
		description = "Trojan:Win32/ClickFix.IIO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
		$a_00_1 = {2e 00 47 00 65 00 74 00 42 00 79 00 74 00 65 00 41 00 72 00 72 00 61 00 79 00 41 00 73 00 79 00 6e 00 63 00 } //1 .GetByteArrayAsync
		$a_00_2 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 .GetString($
		$a_00_3 = {48 00 74 00 74 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 3b 00 24 00 } //1 HttpClient;$
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}