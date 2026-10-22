# DCQL

A simple example:

```json
"dcql_query": {
  "credentials": [
    {
      "id": "my_credential",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "https://credentials.example.com/identity_credential"
        ]
      },
      "claims": [
        { "path": [ "last_name" ] },
        { "path": [ "first_name" ] },
        { "path": [ "address", "street_address" ] }
      ]
    }
  ]
}
```

## 1. What is DCQL?

## Address data query
```json
"dcql_query": {
    "credentials": [
      {
        "id": "pid-sd-jwt",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:eudi:pid:de:1"
          ]
        },
        "claims": [
          {
            "path": [
              "age_equal_or_over",
              "18"
            ]
          },
          {
            "path": [
              "given_name"
            ]
          },
          {
            "path": [
              "family_name"
            ]
          },
          {
            "path": [
              "address",
              "street_address"
            ]
          },
          {
            "path": [
              "address",
              "postal_code"
            ]
          },
          {
            "path": [
              "address",
              "locality"
            ]
          }
        ]
      },
      {
        "id": "pid-mso-mdoc",
        "format": "mso_mdoc",
        "meta": {
          "doctype_value": "eu.europa.ec.eudi.pid.1"
        },
        "claims": [
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "age_over_18"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "given_name"
            ],
            "intent_to_retain": true
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "family_name"
            ],
            "intent_to_retain": true
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_street"
            ],
            "intent_to_retain": true
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_postal_code"
            ],
            "intent_to_retain": true
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_city"
            ],
            "intent_to_retain": true
          }
        ]
      }
    ],
    "credential_sets": [
      {
        "options": [
          [
            "pid-sd-jwt"
          ],
          [
            "pid-mso-mdoc"
          ]
        ]
      }
    ]
  }
```

## SD-JWT & mDOC
```json
"dcql_query": {
    "credentials": [
      {
        "id": "pid-sd-jwt",
        "format": "dc+sd-jwt",
        "claims": [
          {
            "path": [
              "age_equal_or_over",
              "16"
            ]
          }
        ],
        "meta": {
          "vct_values": [
            "urn:eudi:pid:de:1"
          ]
        }
      },
      {
        "id": "pid-mso-mdoc",
        "format": "mso_mdoc",
        "claims": [
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "age_over_16"
            ]
          }
        ],
        "meta": {
          "doctype_value": "eu.europa.ec.eudi.pid.1"
        }
      }
    ],
    "credential_sets": [
      {
        "options": [
          [
            "pid-sd-jwt"
          ],
          [
            "pid-mso-mdoc"
          ]
        ]
      }
    ]
  }
```

## Credential sets

```json
{
  "credentials": [
    {
      "id": "pid_cred",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [ "urn:eudi:pid:1" ]
      },
      "claims": [
        { "path": [ "given_name" ] },
        { "path": [ "family_name" ] },
        { "path": [ "birthdate" ] }
      ]
    },
    {
      "id": "passport_cred",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.eudi.passport.1"
      },
      "claims": [
        { "path": [ "eu.europa.ec.eudi.passport.1", "given_name" ] },
        { "path": [ "eu.europa.ec.eudi.passport.1", "family_name" ] }
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [
        [ "pid_cred" ],
        [ "passport_cred" ]
      ]
    }
  ]
}
```

## Full PID (SD-JWT & mDOC)

```json
"dcql_query": {
    "credentials": [
      {
        "id": "pid-sd-jwt",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:eudi:pid:de:1"
          ]
        },
        "claims": [
          {
            "path": [
              "given_name"
            ]
          },
          {
            "path": [
              "family_name"
            ]
          },
          {
            "path": [
              "birthdate"
            ]
          },
          {
            "path": [
              "address",
              "street_address"
            ]
          },
          {
            "path": [
              "address",
              "postal_code"
            ]
          },
          {
            "path": [
              "address",
              "locality"
            ]
          },
          {
            "path": [
              "address",
              "country"
            ]
          },
          {
            "path": [
              "nationalities"
            ]
          }
        ]
      },
      {
        "id": "pid-mso-mdoc",
        "format": "mso_mdoc",
        "meta": {
          "doctype_value": "eu.europa.ec.eudi.pid.1"
        },
        "claims": [
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "given_name"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "family_name"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "birth_date"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_street"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_postal_code"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_city"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_country"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "nationality"
            ],
            "intent_to_retain": false
          }
        ]
      }
    ],
    "credential_sets": [
      {
        "options": [
          [
            "pid-sd-jwt"
          ],
          [
            "pid-mso-mdoc"
          ]
        ]
      }
    ]
  }
```

## mDL
```json
"dcql_query": {
    "credentials": [
      {
        "id": "mdl",
        "format": "mso_mdoc",
        "meta": {
          "doctype_value": "eu.europa.ec.eudi.mdl.1"
        },
        "claims": [
          {
            "path": [
              "org.iso.18013.5.1",
              "family_name"
            ]
          },
          {
            "path": [
              "org.iso.18013.5.1",
              "given_name"
            ]
          },
          {
            "path": [
              "org.iso.18013.5.1",
              "birth_date"
            ]
          },
          {
            "path": [
              "org.iso.18013.5.1",
              "document_number"
            ]
          },
          {
            "path": [
              "org.iso.18013.5.1",
              "driving_privileges"
            ]
          },
          {
            "path": [
              "org.iso.18013.5.1",
              "expiry_date"
            ]
          },
          {
            "path": [
              "org.iso.18013.5.1",
              "issuing_authority"
            ]
          },
          {
            "path": [
              "org.iso.18013.5.1",
              "un_distinguishing_sign"
            ]
          }
        ]
      }
    ]
  }
```

## PID and diploma
```json
"dcql_query": {
    "credentials": [
      {
        "id": "pid-sd-jwt",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:eudi:pid:de:1"
          ]
        },
        "claims": [
          {
            "path": [
              "given_name"
            ]
          },
          {
            "path": [
              "family_name"
            ]
          },
          {
            "path": [
              "birthdate"
            ]
          },
          {
            "path": [
              "address",
              "street_address"
            ]
          },
          {
            "path": [
              "address",
              "postal_code"
            ]
          },
          {
            "path": [
              "address",
              "locality"
            ]
          },
          {
            "path": [
              "address",
              "country"
            ]
          },
          {
            "path": [
              "nationalities"
            ]
          }
        ]
      },
      {
        "id": "pid-mso-mdoc",
        "format": "mso_mdoc",
        "meta": {
          "doctype_value": "eu.europa.ec.eudi.pid.1"
        },
        "claims": [
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "given_name"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "family_name"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "birth_date"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_street"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_postal_code"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_city"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_country"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "nationality"
            ],
            "intent_to_retain": false
          }
        ]
      },
      {
        "id": "diploma",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:eudi:eaa:university-diploma:1"
          ]
        }
      }
    ],
    "credential_sets": [
      {
        "options": [
          [
            "pid-sd-jwt",
            "diploma"
          ],
          [
            "pid-mso-mdoc",
            "diploma"
          ]
        ]
      }
    ]
  }
```

```json
"dcql_query": {
    "credentials": [
      {
        "id": "pid-sd-jwt",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:eudi:pid:de:1"
          ]
        },
        "claims": [
          {
            "path": [
              "given_name"
            ]
          },
          {
            "path": [
              "family_name"
            ]
          },
          {
            "path": [
              "birthdate"
            ]
          },
          {
            "path": [
              "address",
              "street_address"
            ]
          },
          {
            "path": [
              "address",
              "postal_code"
            ]
          },
          {
            "path": [
              "address",
              "locality"
            ]
          },
          {
            "path": [
              "address",
              "country"
            ]
          },
          {
            "path": [
              "nationalities"
            ]
          }
        ]
      },
      {
        "id": "pid-mso-mdoc",
        "format": "mso_mdoc",
        "meta": {
          "doctype_value": "eu.europa.ec.eudi.pid.1"
        },
        "claims": [
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "given_name"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "family_name"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "birth_date"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_street"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_postal_code"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_city"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_country"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "nationality"
            ],
            "intent_to_retain": false
          }
        ]
      },
      {
        "id": "diploma",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:eudi:eaa:university-diploma:1"
          ]
        }
      }
    ],
    "credential_sets": [
      {
        "options": [
          [
            "pid-sd-jwt",
            "diploma"
          ],
          [
            "pid-mso-mdoc",
            "diploma"
          ]
        ]
      }
    ]
  }
```

## PID or Honorary Card

```json
"dcql_query": {
    "credentials": [
      {
        "id": "pid-sd-jwt",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:eudi:pid:de:1"
          ]
        },
        "claims": [
          {
            "path": [
              "given_name"
            ]
          },
          {
            "path": [
              "family_name"
            ]
          },
          {
            "path": [
              "age_equal_or_over",
              "18"
            ]
          },
          {
            "path": [
              "address",
              "postal_code"
            ]
          },
          {
            "path": [
              "address",
              "locality"
            ]
          }
        ]
      },
      {
        "id": "pid-mso-mdoc",
        "format": "mso_mdoc",
        "meta": {
          "doctype_value": "eu.europa.ec.eudi.pid.1"
        },
        "claims": [
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "given_name"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "family_name"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "age_over_18"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_postal_code"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "eu.europa.ec.eudi.pid.1",
              "resident_city"
            ],
            "intent_to_retain": false
          }
        ]
      },
      {
        "id": "first-aid",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:de:eaa:first-aid-certificate:1"
          ]
        },
        "claims": [
          {
            "path": [
              "given_name"
            ]
          },
          {
            "path": [
              "family_name"
            ]
          },
          {
            "path": [
              "course_type"
            ]
          },
          {
            "path": [
              "course_date"
            ]
          },
          {
            "path": [
              "valid_until"
            ]
          },
          {
            "path": [
              "training_provider"
            ]
          },
          {
            "path": [
              "certificate_id"
            ]
          }
        ]
      },
      {
        "id": "ehrenamtskarte",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:de:eaa:ehrenamtskarte:1"
          ]
        },
        "claims": [
          {
            "path": [
              "card_id"
            ]
          }
        ]
      }
    ],
    "credential_sets": [
      {
        "options": [
          [
            "pid-sd-jwt"
          ],
          [
            "pid-mso-mdoc"
          ]
        ]
      },
      {
        "options": [
          [
            "first-aid"
          ],
          [
            "ehrenamtskarte"
          ]
        ]
      }
    ]
  }
```