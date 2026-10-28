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
        "vct_values": ["urn:eudi:pid:1"]
      },
      "claims": [
        { "path": ["given_name"] },
        { "path": ["family_name"] },
        { "path": ["birthdate"] }
      ]
    },
    {
      "id": "passport_cred",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.eudi.passport.1"
      },
      "claims": [
        { "path": ["eu.europa.ec.eudi.passport.1", "given_name"] },
        { "path": ["eu.europa.ec.eudi.passport.1", "family_name"] }
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [["pid_cred"], ["passport_cred"]]
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

## OR

```json
{
  "credentials": [
    {
      "id": "pid_query",
      "format": "mdoc",
      "meta": {
        "doctype": "eu.europa.ec.eudi.pid.1"
      },
      "claims": [
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "claim": "family_name"
        },
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "claim": "given_name"
        }
      ]
    },
    {
      "id": "mdl_query",
      "format": "mdoc",
      "meta": {
        "doctype": "org.iso.18013.5.1.mDL"
      },
      "claims": [
        {
          "namespace": "org.iso.18013.5.1",
          "claim": "family_name"
        },
        {
          "namespace": "org.iso.18013.5.1",
          "claim": "given_name"
        }
      ]
    }
  ],
  "credential_sets": [
    {
      "id": "identity_or_driving_license",
      "options": [["pid_query"], ["mdl_query"]]
    }
  ]
}
```

## AND

```json
{
  "credentials": [
    {
      "id": "pid_identity_query",
      "format": "mdoc",
      "meta": {
        "doctype": "eu.europa.ec.eudi.pid.1"
      },
      "claims": [
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "claim": "family_name"
        },
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "claim": "given_name"
        }
      ]
    },
    {
      "id": "mdl_driving_query",
      "format": "mdoc",
      "meta": {
        "doctype": "org.iso.18013.5.1.mDL"
      },
      "claims": [
        {
          "namespace": "org.iso.18013.5.1",
          "claim": "driving_privileges"
        }
      ]
    }
  ],
  "credential_sets": [
    {
      "id": "identity_and_license_required",
      "options": [["pid_identity_query", "mdl_driving_query"]]
    }
  ]
}
```

## AND OR

```json
{
  "credentials": [
    {
      "id": "required_pid",
      "format": "mdoc",
      "meta": {
        "doctype": "eu.europa.ec.eudi.pid.1"
      },
      "claims": [
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "claim": "family_name"
        },
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "claim": "given_name"
        }
      ]
    },
    {
      "id": "optional_mdl",
      "format": "mdoc",
      "meta": {
        "doctype": "org.iso.18013.5.1.mDL"
      },
      "claims": [
        {
          "namespace": "org.iso.18013.5.1",
          "claim": "document_number"
        }
      ]
    },
    {
      "id": "optional_ehic",
      "format": "vc+sd-jwt",
      "meta": {
        "vct": "eu.europa.ec.eudi.ehic.1"
      },
      "claims": [
        {
          "claim": "institution_id"
        }
      ]
    }
  ],
  "credential_sets": [
    {
      "id": "complex_verification_flow",
      "options": [
        ["required_pid", "optional_mdl"],
        ["required_pid", "optional_ehic"]
      ]
    }
  ]
}
```

## DE PID (SD-JWT)

VCT value: `urn:eudi:pid:de:1`

### 1. Core Claims

- `family_name` - last name
- `given_name` - first name
- `birthdate` - date of birth
- `birth_family_name` - family name at time of birth
- `sex` - gender
- `nationalities` (represented as array with country codes)
- `place_of_birth` (nested object)
  - `locality` - city
  - `country` - country

### 2. Address Claims

- `address.street_address` - street name
- `address.locality` - city
- `address.postal_code` - ZIP code
- `address.country` - country
- `address.region` - state

### 3. Age Attestations

- `age_equal_or_over` (boolean) - flag, possible values: [12, 14, 16, 18, 21, 65]
- `age_in_years` - calculated age
- `age_birth_year` - birth year

### 4. Document Metadata

- `ìssuance_date` - date of issuance
- `expiry_date` - expiry date of the credential
- `issuing_authority` - authority
- `issuing_country` - country

### Example

```json
{
  "credentials": [
    {
      "id": "german_pid_query",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["urn:eudi:pid:de:1"]
      },
      "claims": [
        { "path": ["given_name"] },
        { "path": ["family_name"] },
        { "path": ["age_equal_or_over", "18"] }
      ]
    }
  ]
}
```

## DE PID (ISO 18013-5 mDOC)

### 1. Standard Namespace (eu.europa.ec.eudi.pid.1)

#### Mandatory Attributes

- `family_name` - last name
- `given_name` - first name
- `birth_date` - date of birth
- `birth_place` - place of birth (pre-formatted string)
- `nationality` - person's nationality (code in accordance with ISO 3166-1 alpha-2)
- `person_identifier` - issuer specific ID (not necessarily identical to the ID card number)

#### Optional Attributes

- `resident_address` - residency address (text block)
- `resident_country` - residency country
- `resident_postal_code`- residency ZIP coxde
- `resident_city`- residency city
- `resident_street`- residency street name
- `resident_house_number`- residency house number
- `gender`- person's gender (encoded as per ISO/IEC 5218)
- `family_name_birth` - last name at birth (if deviating)
- `given_name_birth`- first name at birth

### 2. Metadata Namespace (eu.europa.ec.eudi.pid.metadata.1)

- `issuance_date`- issuance date of PID
- `expiry_date` - expiration date of the credential
- `issuing_authority` - issuing authority or provider (e.g. Bundesdruckerei)
- `issuing_country` - country that was issuing the PID (e.g. "DE")
- `document_number` - identification number of the credential

### 3. Age Attestations

- `age_over_18` (true / false)
- `age_over_16` (true / false)

Note: additional age flags age_over_21, age_over_65) may be added with the final specification.

### 4. Domestic Namespace (eu.europa.ec.eudi.pid.de.1)

- `academic_title` - academic degree
- `also_known_as` - alternative / artist name of the person
- `birth_name` - birth name
- `place_of_birth.no_place_info` - boolean flag for cases where no place of birth is registered (e.g. historic reason, foreign registers)
- `age_over_n` [12, 14, 16, 18, 21, 65] - age flags
- `birth_date` - date of birth with inclusion of "00" as valid values for day and month in case the precise date is not known

### Example

```json
{
  "credentials": [
    {
      "id": "mdoc_pid_query",
      "format": "mso_mdoc",
      "meta": {
        "doctype_values": ["eu.europa.ec.eudi.pid.1"]
      },
      "claims": [
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "element_id": "given_name"
        },
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "element_id": "family_name"
        },
        {
          "namespace": "eu.europa.ec.eudi.pid.1",
          "element_id": "age_over_18"
        }
      ]
    }
  ]
}
```
