package com.solidsign.examples.control;

import com.solidsign.examples.response.PreparedHashesResponse;
import com.solidsign.examples.response.SignResponse;
import com.solidsign.examples.service.XmlPkcs1Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

/**
 * [EN]    REST controller for two-step XAdES (XML) signing using PKCS#1 (external private key).
 *         Step 1: preparation — SolidSign computes and returns hashes.
 *         Step 2: finalization — browser extension signs the hashes and sends the signature values back.
 *
 * [PT-BR] Controller REST para assinatura XAdES (XML) em dois passos com PKCS#1 (chave privada externa).
 *         Passo 1: preparação — o SolidSign calcula e devolve os hashes.
 *         Passo 2: finalização — a extensão do browser assina os hashes e envia os valores de volta.
 *
 * [ES]    Controller REST para firma XAdES (XML) en dos pasos con PKCS#1 (clave privada externa).
 *         Paso 1: preparación — SolidSign calcula y devuelve los hashes.
 *         Paso 2: finalización — la extensión del navegador firma los hashes y envía los valores de vuelta.
 */
@RestController
@RequestMapping("/api/xml")
public class XmlPkcs1Controller {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlPkcs1Controller.class);

    @Autowired
    private XmlPkcs1Service service;

    /**
     * [EN]    STEP 1 — Receives XML document(s) and returns hashes + finalNonce for the browser extension.
     * [PT-BR] PASSO 1 — Recebe documento(s) XML e retorna hashes + finalNonce para a extensão do browser.
     * [ES]    PASO 1 — Recibe documento(s) XML y devuelve hashes + finalNonce para la extensión del navegador.
     */
    @PostMapping("/prepare")
    public ResponseEntity<PreparedHashesResponse> prepare(
            @RequestParam("document") MultipartFile[] documents) throws IOException {
        LOGGER.info("XML PKCS1 preparation request for {} document(s).", documents.length);
        PreparedHashesResponse response = service.prepareSignature(documents);
        return response != null
                ? ResponseEntity.ok(response)
                : ResponseEntity.internalServerError().build();
    }

    /**
     * [EN]    STEP 2 — Receives finalNonce + signatureValue[i] from the browser extension and finalizes signing.
     * [PT-BR] PASSO 2 — Recebe finalNonce + signatureValue[i] da extensão do browser e finaliza a assinatura.
     * [ES]    PASO 2 — Recibe finalNonce + signatureValue[i] de la extensión del navegador y finaliza la firma.
     */
    @PostMapping("/finalize")
    public ResponseEntity<SignResponse> finalize(
            @RequestParam Map<String, String> allParams) {
        LOGGER.info("XML PKCS1 finalization request. finalNonce={}", allParams.get("finalNonce"));
        SignResponse response = service.finalizeSignature(allParams);
        return response != null
                ? ResponseEntity.ok(response)
                : ResponseEntity.internalServerError().build();
    }
}
