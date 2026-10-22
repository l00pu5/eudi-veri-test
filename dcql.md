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

- `family_name`
- `given_name`
- `birthdate`
- `birth_family_name`
- `sex`
- `nationalities` (represented as array with country codes)
- `place_of_birth` (nested object)
  - `locality`
  - `country`

### 2. Address Claims

- `address.street_address`
- `address.locality`
- `address.postal_code`
- `address.country`
- `address.region`

### 3. Age Attestations

- `age_equal_or_over` (boolean) [12, 14, 16, 18, 21, 65]
- `age_in_years`
- `age_birth_year`

### 4. Document Metadata

- `ìssuance_date`
- `expiry_date` (expiry date of the credential)
- `issuing_authority`
- `issuing_country`

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

• family_name: Der aktuelle Nachname der Person.
• given_name: Alle Vornamen der Person.
• birth_date: Das Geburtsdatum.
• birth_place: Der Geburtsort (meist als formatierter Text oder standardisierter String).
• nationality: Die Staatsangehörigkeit (als Code nach ISO 3166-1 alpha-2).
• person_identifier: Ein eindeutiger, kryptografisch geschützter bzw. sektor- oder anbieterspezifischer Identifikator (nicht zwingend die Klartext-Personalausweisnummer).

#### Optional Attributes

• resident_address: Die aktuelle Wohnanschrift (oft als strukturierter Textblock).
• resident_country: Das Land des aktuellen Wohnsitzes.
• resident_postal_code: Die Postleitzahl des Wohnsitzes.
• resident_city: Die Stadt des Wohnsitzes.
• resident_street: Die Straße des Wohnsitzes.
• resident_house_number: Die Hausnummer des Wohnsitzes.
• gender: Das Geschlecht (gemäß ISO/IEC 5218 codiert).
• family_name_birth: Der Geburtsname (falls abweichend).
• given_name_birth: Die Vornamen zum Zeitpunkt der Geburt.

### 2. Metadata Namespace (eu.europa.ec.eudi.pid.metadata.1)

• issuance_date: Das Ausstellungsdatum der PID.
• expiry_date: Das Ablaufdatum der Gültigkeit.
• issuing_authority: Die ausstellende Behörde bzw. der staatlich autorisierte Provider (z. B. das Bundesministerium des Innern / Bundesdruckerei).
• issuing_country: Das Land, welches die PID ausgestellt hat (z. B. "DE").
• document_number: Eine spezifische Identifikationsnummer des digitalen Nachweises.

### 3. Age Attestations

• age_over_18: Gibt true oder false zurück.
• age_over_16: Gibt true oder false zurück.
• Hinweis: Je nach finaler Spezifikation des Profils sind auch Schwellenwerte wie age_over_21 oder age_over_65 als eigenständige Boolean-Elemente definiert.

### 4. Domestic Namespace (eu.europa.ec.eudi.pid.de.1)

• academic_title: Der akademische Grad (z. B. „Dr.“), da dieser im deutschen Personalausweisrecht ein offizieller Namensbestandteil ist.
• also_known_as: Der Ordens- oder Künstlername der Person.
• birth_name: Der Geburtsname wurde aus dem europäischen Standardraum entfernt und im deutschen Namespace als eigenständiges Feld verankert.
• place_of_birth.no_place_info: Ein boolesches Flag für Sonderfälle im deutschen Meldewesen, wenn über den Geburtsort amtlich keine genauen Daten vorliegen (z. B. bei bestimmten historischen oder ausländischen Geburtsregistern).
• age_over_n (wobei n für die Werte 12, 14, 16, 18, 21, 65 steht): Während das europäische Profil primär die Prüfung auf Volljährigkeit (age_over_18) im globalen Namespace vorschreibt, wurden die detaillierten, für das deutsche Recht relevanten Altersgrenzen (z. B. Religionsmündigkeit mit 14, Jugendmedienschutz/Mofaführerschein mit 16, Abgabe hochprozentigen Alkohols mit 18) als separate Flags in den nationalen Namespace eu.europa.ec.eudi.pid.de.1 überführt.
• birth_date (Sonderformate): Der deutsche Namespace unterstützt explizit Geburtsdaten, bei denen der Tag (DD) oder sowohl Monat als auch Tag (MM-DD) den Wert Null (00) aufweisen. Dies ist im deutschen Melderecht für Personen erforderlich, deren exakter Geburtstag oder -monat amtlich nicht bekannt ist (wird auf dem physischen Ausweis als XX.XX.YYYY oder XX.MM.YYYY dargestellt).

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
