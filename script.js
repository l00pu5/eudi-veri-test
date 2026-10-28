let pollInterval = null;
let activeSessionId = null;

let availableScenarios = {};

function loadScenarios() {
  fetch('/api/scenarios')
    .then(res => res.json())
    .then(data => {
      if (data.success && data.scenarios) {
        availableScenarios = data.scenarios;
        const select = document.getElementById('rp-scenario-select');
        if (!select) return;
        select.innerHTML = '';

        Object.keys(availableScenarios).forEach(id => {
          const sc = availableScenarios[id];
          const option = document.createElement('option');
          option.value = id;
          option.innerText = `${sc.name || id} (${id})`;
          if (id === data.activeScenarioId) {
            option.selected = true;
          }
          select.appendChild(option);
        });

        updateScenarioDescription();
      }
    })
    .catch(err => {
      console.warn("Szenarien konnten nicht geladen werden:", err);
      fetch('/api/scenario')
        .then(r => r.json())
        .then(d => {
          if (d.success && d.scenarioId) {
            const select = document.getElementById('rp-scenario-select');
            if (!select) return;
            select.innerHTML = `<option value="${d.scenarioId}">${d.scenario?.name || d.scenarioId}</option>`;
            const descElem = document.getElementById('rp-scenario-desc');
            if (descElem) descElem.innerText = d.scenario?.description || '';
          }
        })
        .catch(e => console.error("Fallback load error:", e));
    });
}

function updateScenarioDescription() {
  const select = document.getElementById('rp-scenario-select');
  if (!select) return;
  const selectedId = select.value;
  const sc = availableScenarios[selectedId];
  const descElem = document.getElementById('rp-scenario-desc');
  if (descElem) {
    if (sc && sc.description) {
      descElem.innerText = sc.description;
    } else {
      descElem.innerText = '';
    }
  }
}

function onScenarioChange() {
  const select = document.getElementById('rp-scenario-select');
  if (!select) return;
  const scenarioId = select.value;
  updateScenarioDescription();

  fetch('/api/scenario/select', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ scenarioId })
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        console.log(`[Frontend] Szenario gewechselt zu: ${scenarioId}`);
      }
    })
    .catch(err => console.error("Fehler beim Szenariowechsel:", err));
}

window.addEventListener('DOMContentLoaded', () => {
  loadScenarios();
  toggleIssuanceFields();
});


function switchTab(tabId) {
  // Reset active tab button
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.getElementById('tab-btn-' + tabId).classList.add('active');

  // Reset active tab content
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  document.getElementById('tab-content-' + tabId).classList.add('active');

  // Clean up shared areas
  document.getElementById('qr-container').classList.add('hidden');
  document.getElementById('status-container').classList.add('hidden');
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  activeSessionId = null;
  resetUI();
}

function startIssuance() {
  document.getElementById('btn-initiate-issuance').disabled = true;
  document.getElementById('status-container').classList.remove('hidden');
  document.getElementById('status-text').innerText = "Erstelle Mitarbeiter-Ausweis Angebot (OpenID4VCI)...";
  document.getElementById('qr-container').classList.add('hidden');

  const type = document.getElementById('iss-credential-type').value;
  let claims = {};
  const validityDays = parseInt(document.getElementById('iss-validity').value, 10) || 90;

  if (type === 'mso_mdoc') {
    claims = {
      given_name: document.getElementById('iss-given-name').value,
      family_name: document.getElementById('iss-family-name').value,
      birth_date: document.getElementById('iss-birthdate').value,
      driving_privileges: document.getElementById('iss-privileges').value,
      issuing_country: document.getElementById('iss-country').value
    };
  } else if (type === 'employee_sd_jwt') {
    claims = {
      given_name: document.getElementById('iss-given-name').value,
      family_name: document.getElementById('iss-family-name').value,
      employee_id: document.getElementById('iss-employee-id').value,
      department: document.getElementById('iss-department').value,
      role: document.getElementById('iss-role').value,
      vct: "urn:company:employee_id:1"
    };
  } else {
    claims = {
      given_name: document.getElementById('iss-given-name').value,
      family_name: document.getElementById('iss-family-name').value,
      birthdate: document.getElementById('iss-birthdate').value,
      is_over_18: true,
      nationalities: [document.getElementById('iss-nationalities').value],
      address: {
        street_address: document.getElementById('iss-street').value,
        locality: document.getElementById('iss-locality').value,
        postal_code: document.getElementById('iss-zip').value,
        country: document.getElementById('iss-country').value
      }
    };
  }

  fetch('/api/issuance/initiate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ claims, validityDays, format: type })
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        activeSessionId = data.sessionId;

        // QR-Code anzeigen
        document.getElementById('qr-image').src = "https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=" + encodeURIComponent(data.credentialOfferUrl);
        document.getElementById('qr-text').innerText = data.credentialOfferUrl;

        // Session ID anzeigen
        document.getElementById('session-title-label').innerText = "Mitarbeiter-Ausweis Session ID";
        document.getElementById('session-id-display').innerText = data.sessionId;

        document.getElementById('qr-container').classList.remove('hidden');
        document.getElementById('status-text').innerText = "Warte auf Wallet-Kopplung (Ausstellung)...";

        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(() => {
          fetch(`/api/presentation/status?sid=${data.sessionId}`)
            .then(r => r.json())
            .then(statusData => {
              if (statusData.status === 'SUCCESS') {
                clearInterval(pollInterval);
                document.getElementById('status-container').classList.add('hidden');
                alert("Mitarbeiter-Ausweis (EAA) erfolgreich an Wallet ausgestellt!");
                resetUI();
              } else if (statusData.status === 'FAILED') {
                clearInterval(pollInterval);
                alert("Ausstellung fehlgeschlagen: " + statusData.errors.join(", "));
                resetUI();
              }
            })
            .catch(err => console.error("Issuance polling error: ", err));
        }, 2000);
      } else {
        alert("Sitzung konnte nicht initiiert werden.");
        resetUI();
      }
    })
    .catch(err => {
      console.error(err);
      alert("Verbindung zum Server fehlgeschlagen.");
      resetUI();
    });
}

function toggleIssuanceFields() {
  const type = document.getElementById('iss-credential-type').value;
  const pidFields = document.getElementById('iss-pid-only-fields');
  const mdlFields = document.getElementById('iss-mdl-only-fields');
  const empFields = document.getElementById('iss-employee-only-fields');

  if (type === 'mso_mdoc') {
    pidFields.style.display = 'none';
    mdlFields.style.display = 'block';
    if (empFields) empFields.style.display = 'none';
    document.getElementById('iss-validity').value = '3650';
  } else if (type === 'employee_sd_jwt') {
    pidFields.style.display = 'none';
    mdlFields.style.display = 'none';
    if (empFields) empFields.style.display = 'block';
    document.getElementById('iss-validity').value = '365';
  } else {
    pidFields.style.display = 'block';
    mdlFields.style.display = 'none';
    if (empFields) empFields.style.display = 'none';
    document.getElementById('iss-validity').value = '90';
  }
}

function startOnboarding() {
  document.getElementById('session-title-label').innerText = "Onboarding Session ID";
  document.getElementById('btn-initiate').disabled = true;
  document.getElementById('status-container').classList.remove('hidden');
  document.getElementById('qr-container').classList.add('hidden');

  const selectElem = document.getElementById('rp-scenario-select');
  const selectedScenario = selectElem ? selectElem.value : null;
  const url = selectedScenario ? `/api/presentation/initiate?scenario=${encodeURIComponent(selectedScenario)}` : '/api/presentation/initiate';

  // Onboarding Session initiieren
  fetch(url)
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        activeSessionId = data.sessionId;

        // QR-Code anzeigen
        document.getElementById('qr-image').src = "https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=" + encodeURIComponent(data.qrCodeUrl);
        document.getElementById('qr-text').innerText = data.qrCodeUrl;

        // Session ID anzeigen
        document.getElementById('session-id-display').innerText = data.sessionId;

        document.getElementById('qr-container').classList.remove('hidden');

        // Polling starten
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(() => pollSession(data.pollEndpoint), 2000);
      } else {
        alert("Session konnte nicht initiiert werden.");
        resetUI();
      }
    })
    .catch(err => {
      console.error(err);
      alert("Verbindung zum Server fehlgeschlagen.");
      resetUI();
    });
}

function pollSession(endpoint) {
  fetch(endpoint)
    .then(res => res.json())
    .then(data => {
      if (data.status === 'SUCCESS') {
        clearInterval(pollInterval);
        displaySuccess(data);
      } else if (data.status === 'FAILED') {
        clearInterval(pollInterval);
        alert("Kryptografische 4-Säulen-Validierung fehlgeschlagen: " + data.errors.join(", "));
        resetUI();
      }
    })
    .catch(err => console.error("Polling Fehler:", err));
}

function displaySuccess(data) {
  document.getElementById('placeholder').classList.add('hidden');
  document.getElementById('success-view').classList.remove('hidden');
  document.getElementById('status-container').classList.add('hidden');
  document.getElementById('btn-initiate').disabled = false;

  const claims = data.claims || {};
  const isMdoc = data.format === 'ISO mdoc';

  // Dokumenten-Header, Icon und Container anpassen
  const credentialHeader = document.getElementById('credential-header');
  const credentialIcon = document.getElementById('credential-icon-container');
  const credentialType = document.getElementById('credential-type');
  const credentialTitle = document.getElementById('credential-title');

  const claimsPidContainer = document.getElementById('claims-pid-container');
  const claimsMdlContainer = document.getElementById('claims-mdl-container');

  const p1Desc = document.getElementById('pillar1-desc');
  const p2Title = document.getElementById('pillar2-title');
  const p2Desc = document.getElementById('pillar2-desc');

  if (isMdoc) {
    // mDL / mdoc Style
    credentialHeader.className = "credential-header mdoc-style";
    credentialType.innerText = "EUDI Mobile Driving Licence (mDL)";
    credentialTitle.innerText = "Fahrerlaubnis (Klasse B)";

    // mDL Icon (Lenkrad / Auto)
    credentialIcon.innerHTML = `
                    <svg class="btn-icon" style="color: white; height: 1.5rem; width: 1.25rem;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                    </svg>
                `;

    claimsPidContainer.classList.add('hidden');
    claimsMdlContainer.classList.remove('hidden');

    document.getElementById('mdl-given_name').innerText = claims.given_name || 'N/A';
    document.getElementById('mdl-family_name').innerText = claims.family_name || 'N/A';
    document.getElementById('mdl-birthdate').innerText = claims.birth_date || claims.birthdate || 'N/A';
    document.getElementById('mdl-privileges').innerText = claims.driving_privileges || 'B';
    document.getElementById('mdl-country').innerText = claims.issuing_country || 'DE';

    // Pillars anpassen
    p1Desc.innerText = "Digitale Signatur des mDL-Herausgebers erfolgreich über die CBOR-Dokumentenstruktur (mso_mdoc) verifiziert. Die Authentizität der Fahrerlaubnis-Daten ist bewiesen.";
    p2Title.innerText = "Säule 2: mdoc-Session Handover & Gerätebindung";
    p2Desc.innerText = "Kryptografische Signatur über das SessionTranscript gemäß ISO/IEC 18013-5 erfolgreich geprüft. Die Gerätebindung schützt die Führerscheinpräsentation vor Replay-Angriffen.";

    // mdoc Integritäts-Log befüllen
    document.getElementById('sd-jwt-audit').classList.add('hidden');
    document.getElementById('mdoc-audit').classList.remove('hidden');
  } else {
    // PID / SD-JWT Style
    credentialHeader.className = "credential-header pid-style";
    credentialType.innerText = "EUDI Personal Identification Data (PID)";
    credentialTitle.innerText = "Personen-Identitätsnachweis";

    // PID Icon (Ausweis)
    credentialIcon.innerHTML = `
                    <svg class="btn-icon" style="color: white; height: 1.5rem; width: 1.25rem;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.333 0 4 .667 4 2V19a2 2 0 01-2 2H5a2 2 0 01-2-2v-1c0-1.333 2.667-2 4-2z" />
                    </svg>
                `;

    claimsPidContainer.classList.remove('hidden');
    claimsMdlContainer.classList.add('hidden');

    if (claims.employee_id || claims.role || claims.department) {
      credentialHeader.className = "credential-header pid-style";
      credentialType.innerText = "EUDI Company Employee ID";
      credentialTitle.innerText = "Mitarbeiter-Ausweis";
      document.getElementById('claim-given_name').innerText = claims.given_name || 'N/A';
      document.getElementById('claim-family_name').innerText = claims.family_name || 'N/A';
      document.getElementById('claim-birthdate').innerText = claims.employee_id ? claims.employee_id : (claims.birthdate || 'N/A');
      document.getElementById('claim-is_over_18').innerText = claims.role || 'N/A';
      document.getElementById('claim-nationalities').innerText = claims.department || 'N/A';
    } else {
      document.getElementById('claim-given_name').innerText = claims.given_name || 'N/A';
      document.getElementById('claim-family_name').innerText = claims.family_name || 'N/A';
      document.getElementById('claim-birthdate').innerText = claims.birthdate || claims.birth_date || 'N/A';
      document.getElementById('claim-is_over_18').innerText = claims.is_over_18 === true ? 'Ja (über 18 Jahre)' : 'Nein';
      document.getElementById('claim-nationalities').innerText = Array.isArray(claims.nationalities) ? claims.nationalities.join(", ") : (claims.nationalities || 'N/A');
    }

    const address = claims.address || {};
    if (typeof address === 'object') {
      document.getElementById('claim-address').innerHTML = `
                        <p style="font-weight: 600; color: var(--text-primary); margin: 0 0 0.25rem 0;">${address.street_address || ''}</p>
                        <p style="margin: 0 0 0.25rem 0;">${address.postal_code || ''} ${address.locality || ''}</p>
                        <p style="font-size: 0.75rem; color: var(--text-secondary); margin: 0;">${address.country || ''}</p>
                    `;
    } else {
      document.getElementById('claim-address').innerText = address || 'N/A';
    }

    // Pillars auf PID zurücksetzen
    p1Desc.innerText = "Digitale ECDSA-P256-Signatur des PID-Herausgebers (Bundesdruckerei) erfolgreich verifiziert. Die Hashes im übergebenen SD-JWT-Ausweis stimmen mathematisch überein.";
    p2Title.innerText = "Säule 2: Gerätebindung (Device / Holder Key Binding)";
    p2Desc.innerText = "Die kryptografische Geräteprüfung wurde erfolgreich validiert. Die Bindung an das hardwarebasierte Secure Element des Nutzers ist bewiesen.";

    // SD-JWT Integritäts-Log befüllen
    document.getElementById('sd-jwt-audit').classList.remove('hidden');
    document.getElementById('mdoc-audit').classList.add('hidden');

    const disclosureBody = document.getElementById('sd-disclosure-table-body');
    disclosureBody.innerHTML = '';

    const integrityLog = data.integrityLog || [];
    const rawSdList = data.rawSdList || [];
    const revealedHashes = new Set();

    integrityLog.forEach(item => {
      const decoded = item.decoded || [];
      const salt = decoded[0] || 'N/A';
      const key = decoded[1] || 'N/A';
      const val = typeof decoded[2] === 'object' ? JSON.stringify(decoded[2]) : (decoded[2] !== undefined ? decoded[2] : 'N/A');
      revealedHashes.add(item.hash);

      const tr = document.createElement('tr');
      tr.className = "disclosure-row";
      tr.innerHTML = `
                        <td style="font-weight: 700; color: var(--indigo-color);">${key}</td>
                        <td style="color: var(--text-primary); font-weight: 600;">${val}</td>
                        <td style="color: var(--text-secondary);">${salt}</td>
                        <td style="font-family: monospace; font-size: 0.7rem; color: var(--text-secondary);">${item.hash}</td>
                        <td style="text-align: right; color: var(--success-color); font-weight: bold;">✔ Bestanden</td>
                    `;
      disclosureBody.appendChild(tr);
    });

    // Render hidden hashes (unrevealed ones)
    const hiddenList = document.getElementById('sd-hidden-list');
    hiddenList.innerHTML = '';

    let hiddenCount = 0;
    rawSdList.forEach(hash => {
      if (!revealedHashes.has(hash)) {
        hiddenCount++;
        const div = document.createElement('div');
        div.className = "hidden-hash-item";
        div.innerHTML = `
                            <span style="font-family: monospace; font-size: 0.7rem;">SHA-256: ${hash}</span>
                            <span class="hidden-hash-badge">Minimiert (Versteckt)</span>
                        `;
        hiddenList.appendChild(div);
      }
    });

    if (hiddenCount === 0) {
      hiddenList.innerHTML = `<p style="font-size: 0.75rem; color: var(--text-secondary); font-style: italic;">Keine unenthüllten Attribute. Alle übermittelten Hashes wurden offengelegt.</p>`;
    }
  }

  // Transportkanal und Verschlüsselungskarte aktualisieren
  const transportCard = document.getElementById('transport-security-card');
  const iconContainer = document.getElementById('transport-icon-container');
  const badge = document.getElementById('transport-badge');
  const desc = document.getElementById('transport-desc');

  if (data.isEncrypted) {
    // JWE-Verschlüsselter Status
    transportCard.className = "transport-security-card encrypted-style";
    iconContainer.className = "transport-icon-wrapper encrypted";
    iconContainer.innerHTML = `
                    <svg class="btn-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                `;
    badge.className = "transport-badge encrypted";
    badge.innerText = "Ende-zu-Ende verschlüsselt (JWE)";
    desc.innerText = "Die Identitätsdaten wurden auf Anwendungsebene via JSON Web Encryption (JWE) mit dem elliptischen ECDH-Sitzungsschlüssel der Onboarding-Sitzung verschlüsselt. Ein Mitlesen der personenbezogenen Daten auf dem Callback-Kanal (direct_post.jwt) war unmöglich.";
  } else {
    // Unverschlüsselter Status (Plain Fallback / Mock)
    transportCard.className = "transport-security-card plain-style";
    iconContainer.className = "transport-icon-wrapper plain";
    iconContainer.innerHTML = `
                    <svg class="btn-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                `;
    badge.className = "transport-badge plain";
    badge.innerText = "Fallback-Kanal (Unverschlüsselt)";
    desc.innerText = "Die Identitätsdaten wurden im Klartext über den unverschlüsselten direct_post Endpoint empfangen. Dies ist der Fallback-Kanal für unkomplizierte lokale Demozwecke und Shell-basierte Wallet-Simulationsskripte im Test-Harness.";
  }
}

function toggleCryptoAudit() {
  const content = document.getElementById('crypto-audit-content');
  const arrow = document.getElementById('crypto-arrow');
  if (content.classList.contains('hidden')) {
    content.classList.remove('hidden');
    arrow.innerText = '▲';
  } else {
    content.classList.add('hidden');
    arrow.innerText = '▼';
  }
}

function resetUI() {
  document.getElementById('btn-initiate').disabled = false;
  if (document.getElementById('btn-initiate-issuance')) {
    document.getElementById('btn-initiate-issuance').disabled = false;
  }
  document.getElementById('status-container').classList.add('hidden');
}

function copySessionId() {
  if (!activeSessionId) return;

  const successHandler = () => {
    const copyIcon = document.getElementById('copy-icon');
    const checkIcon = document.getElementById('check-icon');
    if (copyIcon && checkIcon) {
      copyIcon.classList.add('hidden');
      checkIcon.classList.remove('hidden');
      setTimeout(() => {
        copyIcon.classList.remove('hidden');
        checkIcon.classList.add('hidden');
      }, 2000);
    }
  };

  const errorHandler = (err) => {
    console.error('Kopieren fehlgeschlagen: ', err);
    const displaySpan = document.getElementById('session-id-display');
    if (displaySpan) {
      const range = document.createRange();
      range.selectNodeContents(displaySpan);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(activeSessionId)
      .then(successHandler)
      .catch(() => {
        fallbackCopy(activeSessionId, successHandler, errorHandler);
      });
  } else {
    fallbackCopy(activeSessionId, successHandler, errorHandler);
  }
}

function fallbackCopy(text, onSuccess, onError) {
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const successful = document.execCommand('copy');
    document.body.removeChild(textarea);
    if (successful) {
      onSuccess();
    } else {
      onError('execCommand returned false');
    }
  } catch (err) {
    onError(err);
  }
}