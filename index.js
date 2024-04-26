const { default: base64url } = require('base64url');
const jose = require('node-jose');
// const fs = require('fs');

async function main() {

  const static_wallet_metadata = {
    "issuer":"https://self-issued.me/v2",
    "authorization_endpoint":"mdoc-openid4vp://",
    "response_types_supported":[
      "vp_token"
    ],
    "vp_formats_supported":{
      "mso_mdoc":{}
    },
    "client_id_schemes_supported":[
      "x509_san_dns"
    ],
    "authorization_encryption_alg_values_supported":[ "ECDH-ES" ], 
    "authorization_encryption_enc_values_supported":[ "A256GCM" ]
  };

  const presentation_definition = {
    "id":"mDL-sample-req",
    "input_descriptors":[
      {
        "id":"org.iso.18013.5.1.mDL ",
        "format":{
          "mso_mdoc":{
            "alg":[
              "ES256",
              "ES384",
              "ES512",
              "EdDSA",
              "ESB256",
              "ESB320",
              "ESB384",
              "ESB512"
            ]
          }
        },
        "constraints":{
          "fields":[
            {
              "path":[
                "$['org.iso.18013.5.1']['birth_date']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['document_number']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['driving_privileges']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['expiry_date']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['family_name']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['given_name']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['issue_date']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['issuing_authority']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['issuing_country']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['portrait']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['un_distinguishing_sign']"
              ],
              "intent_to_retain":false
            }
          ],
          "limit_disclosure":"required"
        }
      }
    ]
  };

  const ephemeral_private_key_reader = {
    "kty":"EC",
    "d":"_Hc7lRd1Zt8sDAb1-pCgI9qS3oobKNa-mjRDhaKjH90",
    "use":"enc",
    "crv":"P-256",
    "x":"xVLtZaPPK-xvruh1fEClNVTR6RCZBsQai2-DrnyKkxg",
    "y":"-5-QtFqJqGwOjEL3Ut89nrE0MeaUp5RozksKHpBiyw0",
    "alg":"ECDH-ES",
    "kid":"P8p0virRlh6fAkh5-YSeHt4EIv-hFGneYk14d8DF51w"
  };

  const ephemeral_public_key_reader = {
    "kty":"EC",
    "use":"enc",
    "crv":"P-256",
    "x":"xVLtZaPPK-xvruh1fEClNVTR6RCZBsQai2-DrnyKkxg",
    "y":"-5-QtFqJqGwOjEL3Ut89nrE0MeaUp5RozksKHpBiyw0",
    "alg":"ECDH-ES",
    "kid":"P8p0virRlh6fAkh5-YSeHt4EIv-hFGneYk14d8DF51w"
  };

  const nonce = "abcdefgh1234567890";
  const state = "34asfd34_34$34";
  const authz_request_parameters = {
    "aud":"https://self-issued.me/v2",
    "response_type":"vp_token",
    presentation_definition,
    "client_metadata":{
      "jwks":{
        "keys":[
          ephemeral_public_key_reader
        ]
      },
      "authorization_encrypted_response_alg":"ECDH-ES",
      "authorization_encrypted_response_enc":"A256GCM",
      "vp_formats":{
        "mso_mdoc":{
          "alg":[ "ES256", "ES384", "ES512", "EdDSA", "ESB256", "ESB320", "ESB384", "ESB512" ]
        }
      },
      "require_signed_request_object":true
    },
    state,
    nonce,
    "client_id":"example.com",
    "client_id_scheme":"x509_san_dns",
    "response_mode":"direct_post.jwt",
    "response_uri":"https://example.com/12345/response"    
  };

  const authz_request_jwt_header = {
    "x5c":[
      "MIICPzCCAeWgAwIBAgIUDmBXx7+19KhwjltDbBW4BE0CRREwCgYIKoZIzj0EAwIwaTELMAkGA1UEBhMCVVQxDzANBgNVBAgMBlV0b3BpYTENMAsGA1UEBwwEQ2l0eTESMBAGA1UECgwJQUNNRSBDb3JwMRAwDgYDVQQLDAdJVCBEZXB0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0yMzEwMDMxNDQ5MzhaFw0yNDA5MjMxNDQ5MzhaMGkxCzAJBgNVBAYTAlVUMQ8wDQYDVQQIDAZVdG9waWExDTALBgNVBAcMBENpdHkxEjAQBgNVBAoMCUFDTUUgQ29ycDEQMA4GA1UECwwHSVQgRGVwdDEUMBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARfLh+cWXq5fWRf9Cwo8VRkp9AAOOLaP3UCi3YY1VDHHEx7lAn9MCXo/vniqL88VFEi1PtT9ODaINVIXZFFjOrYo2swaTAdBgNVHQ4EFgQUxv6HtRQk9q7ASQCUqOqEun5S8QQwHwYDVR0jBBgwFoAUxv6HtRQk9q7ASQCUqOqEun5S8QQwDwYDVR0TAQH/BAUwAwEB/zAWBgNVHREEDzANggtleGFtcGxlLmNvbTAKBggqhkjOPQQDAgNIADBFAiBt5/maixJyaWNKG8W9dAePhvhh5OHjswJaEjcyYiqoogIhANwTGTdg12REzQMfQSXTSVtNp1jjJMPsipqR7kIK1JdT"
    ],
    "typ":"JWT",
    "alg":"ES256"
  };

  const static_private_key_reader_auth = {
    "kty":"EC",
    "kid":"Cv_aKIPqB8mkHqcJGUFq7zawf5vAyA6xv3PdJpJY1V8",
    "crv":"P-256",
    "x":"Xy4fnFl6uX1kX_QsKPFUZKfQADji2j91Aot2GNVQxxw",
    "y":"THuUCf0wJej--eKovzxUUSLU-1P04Nog1UhdkUWM6tg",
    "d":"5SOi-q3lIENTg-pyKeh3Vxhvu7IgYRm-IHPis2vfP8c"
  };

  const authz_request_object_jwt = await generate_authz_request_object_jwt(
    static_private_key_reader_auth, authz_request_jwt_header, authz_request_parameters);

  const presentation_submission = {
    "definition_id":"mDL-sample-req",
    "id":"mDL-sample-res",
    "descriptor_map":[
      {
        "id":"org.iso.18013.5.1.mDL",
        "format":"mso_mdoc",
        "path":"$"
      }
    ]
  };

  // contains the base64url-encoded DeviceResponse
  const vp_token = "o2ZzdGF0dXMAZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbGRldmljZVNpZ25lZKJqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhA9f6XRKKl5Ukr0k8j8eJoydBLNE751USDAy3pyJJHzCIQnsOBznJ-8lsINyp8M8EYRWOcLCMwj6VVO35Z2L5y0GpuYW1lU3BhY2Vz2BhBoGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkCvjCCArowggJhoAMCAQICCmCRwzO5rBRkRcIwCgYIKoZIzj0EAwIwJDELMAkGA1UEBhMCVVMxFTATBgNVBAMMDEV4YW1wbGUgSUFDQTAeFw0yNDA0MjQwMzQ5MzVaFw0yNTA0MTkwMzQ5MzVaMC8xCzAJBgNVBAYTAlVTMSAwHgYDVQQDDBdFeGFtcGxlIERvY3VtZW50IFNpZ25lcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPJo0km747h-5ITI-i0p7y-CtMbO5pK4KMNj7dfhOUobYl_I6-qisoAdT3aNh8KR20zOmCQmRMecZY4ts6zt58KjggFuMIIBajAdBgNVHQ4EFgQURZaPbhmqMR-mwk1GSc5L_LVjag4wHwYDVR0jBBgwFoAUiJb9ZNtktggeyaPRNgBppM6LNcYwDgYDVR0PAQH_BAQDAgeAMDsGA1UdEQQ0MDKGMGh0dHBzOi8vaHVkc29uLXRlbmFudC0wMDEudmlpLmF1MzAxLm1hdHRybGFicy5pbzA7BgNVHRIENDAyhjBodHRwczovL2h1ZHNvbi10ZW5hbnQtMDAxLnZpaS5hdTMwMS5tYXR0cmxhYnMuaW8wgYYGA1UdHwR_MH0we6B5oHeGdWh0dHBzOi8vaHVkc29uLXRlbmFudC0wMDEudmlpLmF1MzAxLm1hdHRybGFicy5pby92Mi9jcmVkZW50aWFscy9tb2JpbGUvaWFjYXMvZGVjYjUwYjEtMjM4YS00M2VkLThjZGEtODRkNmJjMDdkYWQ1L2NybDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAoGCCqGSM49BAMCA0cAMEQCICn5xAPEULCcvXM5tWgd0TYXqBGNPoPxtgeOL7w3D4d8AiByje3M6ah8O2eY98D_TklQ8THwflXTZqaVFQLkTmDhW1kCutgYWQK1pmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xqwBYIGhZE1iN3s_JWgA3LZ7cmBLWtNuWvfCG68tUyVJlnPp-AVggdEitfz1XaQbx86pTAAEEkY1z31HgwvBIZbHZDhyhdjQCWCDuRhkEkJ6SxkfOgQrbEhdrBzi5E6YfH9tSsNokWBUOpQNYII2wJsH1-P3mO1wrDLReRVst3Bnl8jncH4ifQgZRSwY7BFggmv7bC1H086Pn94bwWLB1VFFSvaLpkOa6EvgXaJQIHL0FWCC7o453GuK_cXbW8gJbHkZRFQcEkYwbJjrt92d9-O2R2gZYIAtGyoeibvSS4SUTFx-OUywpDdoSjySaf-6ZaCUg1ZHoB1ggyKz8XAW0JPCICcIMwesqGCwVh04o6fJ54Ul4Lm5QHEkIWCArYZCy0spdeMSqhggqR7t9_lLzjjAL-dGFS98EI7YSLwlYIK2o8c8-9Xs1V9iwYIH5eKXRwzoKxv0qVoSQg59Ga_8fClggnBKX7utOjZNkQ2Dw3QupkrNThRL0Nd5Zb-tESNaqzLltZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCDCwq0DBlfBaE527GjHLqdwogiammDoZ-5goAyf1sPxzyJYIJ5wtbMljUQJstSaJL0OsE7actOI2jenuedi7R86CRP9Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbGlkaXR5SW5mb6NpdmFsaWRGcm9twHQyMDI0LTA0LTI1VDIyOjMwOjIwWmp2YWxpZFVudGlswHQyMDI0LTA3LTI0VDAyOjQ5OjI2WmZzaWduZWTAdDIwMjQtMDQtMjVUMjI6Mjk6MjNaWEC9qaRl5XQ5EckqbWBCfmw6z7p5jNYMDQLPwFSFIuwbA8anISKln6ZgDCdhiPVDi0hdrRT4Ldnat8DsFt_iamYGam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xi9gYWQg7pGhkaWdlc3RJRAFmcmFuZG9tUP0nvbvaKGojvN9_3xH4mj1xZWxlbWVudElkZW50aWZpZXJocG9ydHJhaXRsZWxlbWVudFZhbHVlWQft_9j_4AAQSkZJRgABAQAAAAAAAAD_4gIoSUNDX1BST0ZJTEUAAQEAAAIYAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAAHRyWFlaAAABZAAAABRnWFlaAAABeAAAABRiWFlaAAABjAAAABRyVFJDAAABoAAAAChnVFJDAAABoAAAAChiVFJDAAABoAAAACh3dHB0AAAByAAAABRjcHJ0AAAB3AAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAFgAAAAcAHMAUgBHAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFhZWiAAAAAAAABvogAAOPUAAAOQWFlaIAAAAAAAAGKZAAC3hQAAGNpYWVogAAAAAAAAJKAAAA-EAAC2z3BhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABYWVogAAAAAAAA9tYAAQAAAADTLW1sdWMAAAAAAAAAAQAAAAxlblVTAAAAIAAAABwARwBvAG8AZwBsAGUAIABJAG4AYwAuACAAMgAwADEANv_bAEMAEAsMDgwKEA4NDhIREBMYKBoYFhYYMSMlHSg6Mz08OTM4N0BIXE5ARFdFNzhQbVFXX2JnaGc-TXF5cGR4XGVnY__bAEMBERISGBUYLxoaL2NCOEJjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY__AABEIALAAeQMBIgACEQEDEQH_xAAaAAADAQEBAQAAAAAAAAAAAAAAAwQFBgcB_8QALhAAAgIBAwIEBQMFAAAAAAAAAAMEEyMFFDNDUyRjc4MBBhU0oxZEkyU1UVWz_8QAFgEBAQEAAAAAAAAAAAAAAAAAAAME_8QAFhEBAQEAAAAAAAAAAAAAAAAAAAMT_9oADAMBAAIRAxEAPwDlwACSRoAAAAW1CrQGgS7pR93q_wDAFIEu6C0CoAAAAAAAAAFDRQ0AFNGksoBVtrRTQAqqAUFQAN9VoWh6oW-UA1TRvSJbQbykheptoCopUEigAAAAAAFSmq4gktqUSxVWtAbFgNlNOji_LihsBVRsqDVkxm_LiukQfpyUdkNCuTklfK-LK0y5WjNitqaegks9VqqgZODlaW2Ll6QrpG9PVa2pXS5TLnq2srymhJBxFRK1RUriCQAACQAAAglcpfpaiCVympACsnRxVGoogil6g1GjQAkC2ogqbP8AKUX1Daiog2ClKqUo5zVIFVp2Rl6pFtUBwbcQKGz_ALpoqLyhlNAACQAAAllcpfFbUQSuUaFZOoiz1VF6p6u6ckpqhtVqrVBXR2SpQ23KcbAa1rVKOtqtihVVaNtOXlNlKxWios9tuWUB1pK3KSqa1vV9oqy9UDz7VMUpqhUXiKte_ukr1RSsSgy1AAASAChoCmqL1RbVClelaakVVTagrJLFgeUbKqlRaqhtQqVxBqZass9SlNqOoqaqL9-33VHL6Mrx9p2XKqoCDaqbF81uUg-lqt6vpGzAVVFUoaBlxYFTcXEXtt5VKyjahTW1NVUB59PU36o23ujRs_K22olDLUAKAJFDRQ0Bqi-LKqaQDVBWTe3TcWK0lntaNi8QqVFtDUboLVW1HRnJRYErdYjqNq1qlZcoBbU1o1spSuVtXqjasQVEgq23iyg1XLbytKiCfPVAytbiKjktZbbqjf4iAbKlKbKa3utFBgKAAAUNFAA0aKADeit8KNVKtMuA3ul9SmhqbOl1Wl_dOXixVW27pqjZVU391b7oVag3lJVKq4mjbSQGnJfNsrxSldo6OVKqU1rekcHKlbqU2U3qlUqlCgAqygPdAUAAABU0GtFNbUErFiAqi8RswMpgwOIvU2okq62LAVUNVpaldUggT1VZTUVKV3QqbUDQ3XaBSiQy9exaW1rTiG8uI7L5jlKa3a9rK05dtTeWpRVKqACrYYrVNVUKapqiqRQAASXyorVKxKIKi_3be6StVb9r0gqlVyqKmqa1ouL8Pj8Pjj-GVnGbsWKptrWt4lAZcA2dgQKgNixVN7p2UVXhVElWDF0trTZi6MpRepVQ20KhSlKINU1RUBXmip-s7XErlOXlSmz222gakC1Wlyp_VbiMvWVKVFV0ml8ptUCLF7SvymNryqpSovaUEilKtxWim7qBibaoa1VSjU1SA1XErF_yKpMZSlNVlKtr5opTVKblVxF-6i_6v8oCmxdhFU3lt5SVsVsXpNOolRbZSoHutMaU1u6a3KBjZVZTeVPV9LUpTfFN5RWsRlJ0uL3eUlbF2qospXE0DZVlgbXqqOogfaqOD0ue3f5fyneK4sRJqkGmXPlYsRqN4jnJ8rqtJDLlBAV_V2yv2o1VvVVla3ENbK8BUr-JpVI1VUrVMrcSsrfVMGU23VGt801GxZWl6Nl6pgxVNa3EVSXymq3SsuI3lSlSlYuXzTkpSmqlVHRq0tu1U0DLn2qnhaGsKlVKa1Rlkh__2dgYWFukaGRpZ2VzdElEBGZyYW5kb21QTHA3iJAbd81ImASs4_u6t3FlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoxOTkwLTAxLTAx2BhYU6RoZGlnZXN0SUQFZnJhbmRvbVANCsbcq7Su0NHccF3BnhPpcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZUFsaWNl2BhYW6RoZGlnZXN0SUQHZnJhbmRvbVDRNWgv94Vr_gTDxfb8-xeicWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVl2QPsajIwMjAtMDEtMDHYGFhcpGhkaWdlc3RJRAhmcmFuZG9tUF_whAce9RoquZF-wB3I0qBxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVl2QPsajIwMjUtMDEtMDHYGFhUpGhkaWdlc3RJRAZmcmFuZG9tUB3t9jrQhoZSetTw51AfoihxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlZVNtaXRo2BhYW6RoZGlnZXN0SUQAZnJhbmRvbVD7avw7ISDwsaZiRqSbjJgFcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVoQUJDRDEyMzTYGFhVpGhkaWdlc3RJRAJmcmFuZG9tULxxEqk2h5QcA6b7OwTurUJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJVU9gYWFukaGRpZ2VzdElECWZyYW5kb21Q6F76KutwmGh82M-9cmpnunFlbGVtZW50SWRlbnRpZmllcnFpc3N1aW5nX2F1dGhvcml0eWxlbGVtZW50VmFsdWVmTlksVVNB2BhY76RoZGlnZXN0SUQDZnJhbmRvbVCS8il-rW8DNcQzql1AxKkpcWVsZW1lbnRJZGVudGlmaWVycmRyaXZpbmdfcHJpdmlsZWdlc2xlbGVtZW50VmFsdWWCo3V2ZWhpY2xlX2NhdGVnb3J5X2NvZGVhQmppc3N1ZV9kYXRl2QPsajIwMjAtMDEtMDFrZXhwaXJ5X2RhdGXZA-xqMjAyNS0wMS0wMaN1dmVoaWNsZV9jYXRlZ29yeV9jb2RlYkJFamlzc3VlX2RhdGXZA-xqMjAyMC0wMS0wMWtleHBpcnlfZGF0ZdkD7GoyMDI1LTAxLTAx2BhYXaRoZGlnZXN0SUQKZnJhbmRvbVCix79rse-EoYPDEOwsnQYocWVsZW1lbnRJZGVudGlmaWVydnVuX2Rpc3Rpbmd1aXNoaW5nX3NpZ25sZWxlbWVudFZhbHVlY1VTQQ=="

  const authz_response_parameters = {
    presentation_submission,
    vp_token
  };

  const mdoc_generated_nonce = "1234567890abcdefgh";
  const authz_response_object_jwt = await generate_authz_response_object_jwt(
    authz_response_parameters, mdoc_generated_nonce, nonce, ephemeral_public_key_reader);

  const authz_response_jwt_header = JSON.parse(base64url.decode(authz_response_object_jwt.split('.')[0]));

  const ephemeral_private_key_mdoc = {
     // TBD: needs to be read from memory via debugger
  };

  const ephemeral_public_key_mdoc = authz_response_jwt_header.epk;

  // -------
  // OID4VPHandover and SessionTranscriopt using the following params:
  // mdoc_generated_nonce = "1234567890abcdefgh"
  // client_id = "example.com".
  // response_uri = "https://example.com/12345/response"
  // nonce = "abcdefgh1234567890"
  const oid4vp_handover_hex = "835820DA25C527E5FB75BC2DD31267C02237C4462BA0C1BF37071F692E7DD93B10AD0B5820F6ED8E3220D3C59A5F17EB45F48AB70AEECF9EE21744B1014982350BD96AC0C572616263646566676831323334353637383930";
  const session_transcript_hex = "83F6F6835820DA25C527E5FB75BC2DD31267C02237C4462BA0C1BF37071F692E7DD93B10AD0B5820F6ED8E3220D3C59A5F17EB45F48AB70AEECF9EE21744B1014982350BD96AC0C572616263646566676831323334353637383930";
  // -------

  console.log("----------------");
  console.log("Annex B Examples");
  console.log("----------------");

  console.log("-------------------------------");
  console.log("Example: Static Wallet Metadata");
  console.log("-------------------------------");
  console.log(JSON.stringify(static_wallet_metadata, null, 2));

  console.log("--------------------------------");
  console.log("Example: Presentation Definition");
  console.log("--------------------------------");
  console.log(JSON.stringify(presentation_definition, null, 2));

  console.log("-----------------------------------------");
  console.log("Example: Ephemeral Private Reader Key JWK");
  console.log("-----------------------------------------");
  console.log(JSON.stringify(ephemeral_private_key_reader, null, 2));

  console.log("----------------------------------------");
  console.log("Example: Ephemeral Public Reader Key JWK");
  console.log("----------------------------------------");
  console.log(JSON.stringify(ephemeral_public_key_reader, null, 2));

  console.log("------------------------------------------------");
  console.log("Example: Authorization Request Object parameters");
  console.log("------------------------------------------------");
  console.log(JSON.stringify(authz_request_parameters, null, 2));

  console.log("------------------------------------------------------");
  console.log("Example: Authorization Request Object JWT (JAR) Header");
  console.log("------------------------------------------------------");
  console.log(JSON.stringify(authz_request_jwt_header, null, 2));

  console.log("------------------------------------------------------------------------");
  console.log("Example: Static Private Reader Key JWK corresponding to 'x5c' JWT Header");
  console.log("------------------------------------------------------------------------");
  console.log(JSON.stringify(static_private_key_reader_auth, null, 2));

  console.log("----------------------------------------------------------");
  console.log("Example: Authorization Request Object encoded as JWT (JAR)");
  console.log("----------------------------------------------------------");
  console.log(authz_request_object_jwt);

  console.log("--------------------------------");
  console.log("Example: Presentation Submission");
  console.log("--------------------------------");
  console.log(JSON.stringify(presentation_submission, null, 2));

  console.log("-----------------");
  console.log("Example: VP Token");
  console.log("-----------------");
  console.log(vp_token);

  console.log("-------------------------------------------------");
  console.log("Example: Authorization Response Object parameters");
  console.log("-------------------------------------------------");
  console.log(JSON.stringify(authz_response_parameters, null, 2));

  console.log("-----------------------------------------------------------");
  console.log("Example: Authorization Response Object encoded as JWT (JARM)");
  console.log("-----------------------------------------------------------");
  console.log(authz_response_object_jwt);

  console.log("--------------------------------------------------------");
  console.log("Example: Authorization Response Object JWT (JARM) Header");
  console.log("--------------------------------------------------------");
  console.log(JSON.stringify(authz_response_jwt_header, null, 2));

  console.log("--------------------------------------");
  console.log("Example: Ephemeral Public MDOC Key JWK");
  console.log("--------------------------------------");
  console.log(JSON.stringify(ephemeral_public_key_mdoc, null, 2));

  console.log("--------------------------------------");
  console.log("Example: Ephemeral Private MDOC Key JWK");
  console.log("--------------------------------------");
  console.log("In node-jose:encrypt.js: line 196: print the following expresssion: JSON.stringify(epk.toJSON(true, [\"kid\"]), null, 2) ");

  console.log("-----------------------------------------------------------");
  console.log("Example: OID4VPHandover CBOR Hex");
  console.log("-----------------------------------------------------------");
  console.log(oid4vp_handover_hex);

  console.log("-----------------------------------------------------------");
  console.log("Example: SessionTranscipt CBOR Hex");
  console.log("-----------------------------------------------------------");
  console.log(session_transcript_hex);
}

async function generate_authz_request_object_jwt(static_private_key_reader_auth, authz_request_jwt_header, authz_request_parameters) {
  const key = await jose.JWK.asKey(static_private_key_reader_auth);    
  const jwt = await jose.JWS.createSign({ format: 'compact', fields: authz_request_jwt_header }, key).
          update(JSON.stringify(authz_request_parameters)).
          final();
  return jwt;
}

async function generate_authz_response_object_jwt(
  authz_response_parameters, mdoc_generated_nonce, nonce, ephemeral_public_key_reader) {

  const encKey = await jose.JWK.asKey(ephemeral_public_key_reader);
  const apu = base64url(mdoc_generated_nonce);
  const apv = base64url(nonce);

  const jwe = await jose.JWE.createEncrypt({
      format: 'compact',
      fields: {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        apu: apu,
        apv: apv,
        kid: ephemeral_public_key_reader.kid
      },
  }, {
      key: encKey,
  }).update(JSON.stringify(authz_response_parameters)).final();

  return jwe;
}

// async function decrypt_authz_response_jwt_headers(authz_response_object_jwt, ephemeral_private_key_reader) {
//   const decKey = await jose.JWK.asKey(ephemeral_private_key_reader);
//   const decrypted = await jose.JWE.createDecrypt(decKey).decrypt(authz_response_object_jwt);
//   console.log('decrypted: ', JSON.parse(decrypted.payload.toString('utf8')));
// }

// async function extract() {
//   const args = process.argv.slice(2);

//   const key = fs.readFileSync(args[0]);
//   const keystore = jose.JWK.createKeyStore();

//   var DUMP_PRIVATE_KEY = ('true' == args[1]);

//   keystore
//     .add(key, 'pem')
//     .then(function(_) {
//       const jwks = keystore.toJSON(DUMP_PRIVATE_KEY);
//       console.log(JSON.stringify(jwks, null, 4));
//     });
// }

main()
