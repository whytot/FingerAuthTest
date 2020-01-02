package com.bill.fingerauthtest;

public class Constants {
    public static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

    public static final String CLIENT_1_CERTIFICATE =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIID7jCCA5SgAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExAyZGM1OGIyZDFhMjQxMzI2" +
                    "MQwwCgYDVQQMDANURUUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNV" +
                    "BAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHkyl3epG" +
                    "PODlaNT50JG1QK/DTFIz5vkasDfsOMQiKlcrbKwmCTfFJqJcz6z/CKt6x5edTL66YxaQ430d0Is3" +
                    "JKOCArMwggKvMA4GA1UdDwEB/wQEAwIHgDCCApsGCisGAQQB1nkCAREEggKLMIIChwIBAwoBAQIB" +
                    "BAoBAQQDYWJjBAAwggHNv4U9CAIGAWTmEWf/v4VFggG7BIIBtzCCAbMxggGLMAwEB2FuZHJvaWQC" +
                    "AR0wGQQUY29tLmFuZHJvaWQua2V5Y2hhaW4CAR0wGQQUY29tLmFuZHJvaWQuc2V0dGluZ3MCAR0w" +
                    "GQQUY29tLnF0aS5kaWFnc2VydmljZXMCAR0wGgQVY29tLmFuZHJvaWQuZHluc3lzdGVtAgEdMB0E" +
                    "GGNvbS5hbmRyb2lkLmlucHV0ZGV2aWNlcwIBHTAfBBpjb20uYW5kcm9pZC5sb2NhbHRyYW5zcG9y" +
                    "dAIBHTAfBBpjb20uYW5kcm9pZC5sb2NhdGlvbi5mdXNlZAIBHTAfBBpjb20uYW5kcm9pZC5zZXJ2" +
                    "ZXIudGVsZWNvbQIBHTAgBBtjb20uYW5kcm9pZC53YWxscGFwZXJiYWNrdXACAR0wIQQcY29tLmdv" +
                    "b2dsZS5TU1Jlc3RhcnREZXRlY3RvcgIBHTAiBB1jb20uZ29vZ2xlLmFuZHJvaWQuaGlkZGVubWVu" +
                    "dQIBATAjBB5jb20uYW5kcm9pZC5wcm92aWRlcnMuc2V0dGluZ3MCAR0xIgQgMBqjywgRNFAcRfFC" +
                    "KrxmwkIk/V3tX9yPF+aXF2/YZqowgaChCDEGAgECAgEDogMCAQOjBAICAQClBTEDAgEEqgMCAQG/" +
                    "g3cCBQC/hT4DAgEAv4VATDBKBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAoB" +
                    "AgQgco2xJ08fHPFXHeQ4CwSKVUrEo4Dnb1NVCDUpCEqTeAG/hUEDAgEAv4VCBQIDAxSzv4VOBQID" +
                    "AxSzv4VPBQIDAxSzMAoGCCqGSM49BAMCA0gAMEUCIDsINbPXvgn8qN2V74vvO9RcuXe17dswxNkm" +
                    "1vyx1BqCAiEAkicGYwvPJp4jAIZbD9++D+kQJQSJZyE3kT9ukSeSfHs=\n" +
                    "-----END CERTIFICATE-----";
    public static final String GOOGLE_ROOT_CERTIFICATE =
            "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV"
                    + "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy"
                    + "ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B"
                    + "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS"
                    + "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7"
                    + "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj"
                    + "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq"
                    + "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ"
                    + "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O"
                    + "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg"
                    + "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi"
                    + "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M"
                    + "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E"
                    + "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um"
                    + "AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD"
                    + "VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO"
                    + "BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk"
                    + "Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD"
                    + "ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB"
                    + "Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m"
                    + "qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY"
                    + "DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm"
                    + "QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u"
                    + "JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD"
                    + "CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy"
                    + "ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD"
                    + "qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic"
                    + "MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1"
                    + "wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk\n"
                    + "-----END CERTIFICATE-----";
}
