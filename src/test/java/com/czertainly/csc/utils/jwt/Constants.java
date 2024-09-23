package com.czertainly.csc.utils.jwt;

public class Constants {

    public static final String CREDENTIAL_SCOPE = "credential";
    public static final String SERVICE_SCOPE = "service";

    public static final String TEST_ISSUER = "com.czertainly.csc.test-issuer";
    public static final String TEST_AUDIENCE = "com.czertainly.csc.test-audience";

    public static final String JWKS_STRING = """
                {
                  "keys": [
                    {
                      "kid": "gLtlBsaTqoSnqw_5yG_UQltrUPE31aP6KjJZwHlxJAk",
                      "kty": "RSA",
                      "alg": "RS256",
                      "use": "sig",
                      "n": "rIjueCwUn4zzxmpFwMPFV6d4zgMvgdGfkiF_LdiTVwArpjk_7jUFtF_HiGKyHHp6w26qEsQgAt9VjyDnGt5Jqsd9S1W18krMelXpwEF0DRlcz3tEkMKPPiKbyhTNIMX8a6rFYv67tamCURppJuUbXacES1M7ryZOYBu7ctbbH0WgDiFAn8DjBa9W_yXk3bnuELerMMfux37DKecXF8VworDExgGBLQ7Mu3TA0CVHwPwbzwN-1FRCQMNavk6hFRK1szdjMjIH_esuSuEjLs4s7IycjtoODlUCjWBdUbY_gER3Vh6RxPV0Lxt62IHl8GeHRnNXQcoF2wlxZEjjLgBxAQ",
                      "e": "AQAB",
                      "x5c": [
                        "MIICmzCCAYMCBgGQwEoGATANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQwNzE3MTA0MTM1WhcNMzQwNzE3MTA0MzE1WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsiO54LBSfjPPGakXAw8VXp3jOAy+B0Z+SIX8t2JNXACumOT/uNQW0X8eIYrIcenrDbqoSxCAC31WPIOca3kmqx31LVbXySsx6VenAQXQNGVzPe0SQwo8+IpvKFM0gxfxrqsVi/ru1qYJRGmkm5RtdpwRLUzuvJk5gG7ty1tsfRaAOIUCfwOMFr1b/JeTdue4Qt6swx+7HfsMp5xcXxXCisMTGAYEtDsy7dMDQJUfA/BvPA37UVEJAw1q+TqEVErWzN2MyMgf96y5K4SMuzizsjJyO2g4OVQKNYF1Rtj+ARHdWHpHE9XQvG3rYgeXwZ4dGc1dBygXbCXFkSOMuAHEBAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHl9DMFesh1rvA2xo68UJykODQVteWrCFwwucw0swN0MG38aNJDDXbUk0FwZvr2qRizGEJUKb6BcZmptv8IaQwdFRPSYLNPBhoB58g+qYkJ1kF9ZSydUEvBZ9n+NsyU08bOvPjVPPUQkZ5MEtmplU9VBtrlBoDtlMV7O977uSQhPhU/moqFyz2IunzxZyipxZrDHhP3ta4x7zQe3TT5Q9JHKHj6HeUyXqlC5M5+LvYkdw4XhwwS9i5TgKFqmTG66SXUBM6CkO9qtgWb7eumDbj+ZJ0NfAyDtlf37FWhX/cu7YdHkr2X+K0i28V6XcYcs8q/KpiChMF6OOvM9UKwY3IE="
                      ],
                      "x5t": "sAQuVuihoOb3-cQfnGYOGvQEBA4",
                      "x5t#S256": "kOXOYP27ixlN9wQE3GkzkoVJr9c0IvlmFDAWyaHU2Fk"
                    },
                    {
                      "kid": "K4jv1PJukvHi_e2F3IyWRwPSmf6aADwBkHs5Hs5H85E",
                      "kty": "RSA",
                      "alg": "RSA-OAEP",
                      "use": "enc",
                      "n": "8zQz2Oq8zdzMD7iitm26On0AiKV1VuFmUfEXuEai_lBxbVkMEQZJbInPmRRTmLNm7YyAYlPSe05zSd1ep-LHd7GCKmltv7Nzz0s5_RWzrU1Lg1E92OTS0FOcflb-vZBpFU3JHe2-yCpgtfEZcWBzpsBreacDvlPzsZqWUbkc_Wh7WtT3Ywa6pnaE2MDh0xNSrL18gA4B0SRL4dSas85-s4PnL9EpdDmIykNc-j3YSRsuG5B8f-wz-mSxecAvG6wSxITo4q2x_-3TxM7pLk5ylqzx5t5EIXkW_i0Wq6pO8HydgYP5m5wxJ6u3whBbXZlTXlxklco3Tt9EKdZwAbUdWw",
                      "e": "AQAB",
                      "x5c": [
                        "MIICmzCCAYMCBgGQwEoGYzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQwNzE3MTA0MTM1WhcNMzQwNzE3MTA0MzE1WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDzNDPY6rzN3MwPuKK2bbo6fQCIpXVW4WZR8Re4RqL+UHFtWQwRBklsic+ZFFOYs2btjIBiU9J7TnNJ3V6n4sd3sYIqaW2/s3PPSzn9FbOtTUuDUT3Y5NLQU5x+Vv69kGkVTckd7b7IKmC18RlxYHOmwGt5pwO+U/OxmpZRuRz9aHta1PdjBrqmdoTYwOHTE1KsvXyADgHRJEvh1Jqzzn6zg+cv0Sl0OYjKQ1z6PdhJGy4bkHx/7DP6ZLF5wC8brBLEhOjirbH/7dPEzukuTnKWrPHm3kQheRb+LRarqk7wfJ2Bg/mbnDEnq7fCEFtdmVNeXGSVyjdO30Qp1nABtR1bAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMgaAJ42t7kCmY9N+1+pKPWUe9yY5k0OAIGKAjenQmudRm46SwyxgCYZIbZaJ2TrMlR66W+A3XI+xcGuKNvWk0TEmIENHIT4LwhOSi3SerrjX/K31khtSN0YapfhjbAq5PKU43fmky7zSOG01Ni770H/9RagHB/vH+0Iq8d1Ekq1jdah2oV2QhORqeswQOkj/rOg+XbgKchjCjN2tV1Pw1NKFo5miQ370f/s9IBjxvo9ZlHRvHmqH03CGZ4UkFLTFPKYF0UB6TrTi9jsWl71pXbI5f4SXEQNEwmbM5ZdyYwbvHSbcL0WLcIV/+4T7Y2m0McWKTCx98XVfVVLuf8YJRo="
                      ],
                      "x5t": "6ByroQAgFI_13N-8syaTd3s22cY",
                      "x5t#S256": "dYB9Wlo72L4sHwM2FyeSzR0qvejmhmXKOeayuQPAKoU"
                    }
                  ]
                }
                """;


}
