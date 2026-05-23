package com.solidsign.examples.service;

import com.solidsign.examples.response.PreparedHashesResponse;
import com.solidsign.examples.response.SignResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

/**
 * [EN]    Service for two-step XAdES (XML) signing using PKCS#1 (external private key).
 *         The private key never leaves the client device; only the public certificate PEM is sent here.
 *         Flow:
 *           1. prepareSignature — sends documents + certificate to SolidSign; receives hashes + finalNonce.
 *           2. finalizeSignature — sends finalNonce + signed hashes; receives download links.
 *
 * [PT-BR] Serviço para assinatura XAdES (XML) em dois passos com PKCS#1 (chave privada externa).
 *         A chave privada nunca sai do dispositivo do cliente; apenas o PEM do certificado público é enviado aqui.
 *         Fluxo:
 *           1. prepareSignature — envia documentos + certificado ao SolidSign; recebe hashes + finalNonce.
 *           2. finalizeSignature — envia finalNonce + hashes assinados; recebe links para download.
 *
 * [ES]    Servicio para firma XAdES (XML) en dos pasos con PKCS#1 (clave privada externa).
 *         La clave privada nunca sale del dispositivo del cliente; solo se envía el PEM del certificado público.
 *         Flujo:
 *           1. prepareSignature — envía documentos + certificado a SolidSign; recibe hashes + finalNonce.
 *           2. finalizeSignature — envía finalNonce + hashes firmados; recibe enlaces de descarga.
 */
@Service
public class XmlPkcs1Service {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlPkcs1Service.class);
    private final RestTemplate restTemplate = new RestTemplate();

    // [EN]    Base URL of the SolidSign API
    // [PT-BR] URL base da API SolidSign
    // [ES]    URL base de la API SolidSign
    @Value("${solidsign.api.base-url}")
    private String baseUrl;

    // [EN]    Authorization header value (Bearer token)
    // [PT-BR] Valor do header Authorization (token Bearer)
    // [ES]    Valor del header Authorization (token Bearer)
    @Value("${solidsign.api.authorization}")
    private String authorization;

    // [EN]    Signature profile (e.g. ADRB, ADRT, ADRC, ADRA)
    // [PT-BR] Perfil de assinatura (ex: ADRB, ADRT, ADRC, ADRA)
    // [ES]    Perfil de firma (p.ej. ADRB, ADRT, ADRC, ADRA)
    @Value("${solidsign.sig.profile}")
    private String profile;

    // [EN]    Hash algorithm (SHA256, SHA384, SHA512)
    // [PT-BR] Algoritmo de hash (SHA256, SHA384, SHA512)
    // [ES]    Algoritmo de hash (SHA256, SHA384, SHA512)
    @Value("${solidsign.sig.hashAlgorithm}")
    private String hashAlgorithm;

    // [EN]    Signature packaging (ENVELOPED, ENVELOPING, DETACHED)
    // [PT-BR] Empacotamento da assinatura (ENVELOPED, ENVELOPING, DETACHED)
    // [ES]    Empaquetado de la firma (ENVELOPED, ENVELOPING, DETACHED)
    @Value("${solidsign.sig.signaturePackaging}")
    private String signaturePackaging;

    // [EN]    Local name of the XML node to sign
    // [PT-BR] Nome local do nó XML a assinar
    // [ES]    Nombre local del nodo XML a firmar
    @Value("${solidsign.sig.signatureNodeName}")
    private String signatureNodeName;

    // [EN]    Namespace URI of the XML node to sign
    // [PT-BR] URI de namespace do nó XML a assinar
    // [ES]    URI de namespace del nodo XML a firmar
    @Value("${solidsign.sig.signatureNodeNamespace}")
    private String signatureNodeNamespace;

    // [EN]    XML canonicalization algorithm URI
    // [PT-BR] URI do algoritmo de canonicalização XML
    // [ES]    URI del algoritmo de canonicalización XML
    @Value("${solidsign.sig.canonicalizationMethod}")
    private String canonicalizationMethod;

    // [EN]    PEM body of the signer's public certificate (no BEGIN/END headers, no private key)
    // [PT-BR] Corpo PEM do certificado público do assinante (sem marcadores BEGIN/END, sem chave privada)
    // [ES]    Cuerpo PEM del certificado público del firmante (sin marcadores BEGIN/END, sin clave privada)
    @Value("${solidsign.cert.pem}")
    private String signerCertPem;

    /**
     * [EN]    Sends XML documents and the signer certificate to SolidSign sign-preparation endpoint.
     *         Returns hashes and finalNonce for the browser extension to sign.
     *
     * [PT-BR] Envia documentos XML e o certificado do assinante para o endpoint sign-preparation do SolidSign.
     *         Retorna hashes e finalNonce para a extensão do browser assinar.
     *
     * [ES]    Envía documentos XML y el certificado del firmante al endpoint sign-preparation de SolidSign.
     *         Devuelve hashes y finalNonce para que la extensión del navegador los firme.
     */
    public PreparedHashesResponse prepareSignature(MultipartFile[] documents) throws IOException {
        // [EN]    Build preparation URL from the base URL
        // [PT-BR] Constrói a URL de preparação a partir da URL base
        // [ES]    Construye la URL de preparación a partir de la URL base
        String prepUrl = baseUrl + "/solidsign/dsig/xml/pkcs1/sign-preparation";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", authorization);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        for (int i = 0; i < documents.length; i++) {
            final byte[] bytes = documents[i].getBytes();
            final String name  = documents[i].getOriginalFilename();
            body.add("document[" + i + "]", new ByteArrayResource(bytes) {
                @Override public String getFilename() { return name; }
            });
        }
        body.add("profile",                profile);
        body.add("hashAlgorithm",          hashAlgorithm);
        body.add("signaturePackaging",     signaturePackaging);
        body.add("signatureNodeName",      signatureNodeName);
        body.add("signatureNodeNamespace", signatureNodeNamespace);
        body.add("canonicalizationMethod", canonicalizationMethod);
        // [EN]    Signer's certificate PEM body (no headers) — required by SolidSign to embed it in the signature
        // [PT-BR] Corpo PEM do certificado do assinante (sem marcadores) — obrigatório para SolidSign embutir na assinatura
        // [ES]    Cuerpo PEM del certificado del firmante (sin marcadores) — requerido por SolidSign para incluirlo en la firma
        body.add("certificate", signerCertPem);

        try {
            ResponseEntity<PreparedHashesResponse> resp = restTemplate.postForEntity(
                    prepUrl, new HttpEntity<>(body, headers), PreparedHashesResponse.class);
            if (resp.getStatusCode() == HttpStatus.OK) {
                LOGGER.info("XML PKCS1 preparation OK. finalNonce={}", resp.getBody().finalNonce);
                return resp.getBody();
            }
        } catch (HttpStatusCodeException e) {
            LOGGER.error("SolidSign prep error {}: {}", e.getStatusCode(), e.getResponseBodyAsString());
        } catch (Exception e) {
            LOGGER.error("Unexpected error during XML preparation: {}", e.getMessage(), e);
        }
        return null;
    }

    /**
     * [EN]    Sends finalNonce and signature values to SolidSign sign-finalization endpoint.
     *         allParams must contain: finalNonce, signatureValue[0], signatureValue[1], ...
     *
     * [PT-BR] Envia finalNonce e valores de assinatura para o endpoint sign-finalization do SolidSign.
     *         allParams deve conter: finalNonce, signatureValue[0], signatureValue[1], ...
     *
     * [ES]    Envía finalNonce y valores de firma al endpoint sign-finalization de SolidSign.
     *         allParams debe contener: finalNonce, signatureValue[0], signatureValue[1], ...
     */
    public SignResponse finalizeSignature(Map<String, String> allParams) {
        // [EN]    Build finalization URL from the base URL
        // [PT-BR] Constrói a URL de finalização a partir da URL base
        // [ES]    Construye la URL de finalização a partir de la URL base
        String finalUrl = baseUrl + "/solidsign/dsig/xml/pkcs1/sign-finalization";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", authorization);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        allParams.forEach(body::add);

        try {
            ResponseEntity<SignResponse> resp = restTemplate.postForEntity(
                    finalUrl, new HttpEntity<>(body, headers), SignResponse.class);
            if (resp.getStatusCode() == HttpStatus.OK) {
                LOGGER.info("XML PKCS1 finalization OK.");
                return resp.getBody();
            }
        } catch (HttpStatusCodeException e) {
            LOGGER.error("SolidSign final error {}: {}", e.getStatusCode(), e.getResponseBodyAsString());
        } catch (Exception e) {
            LOGGER.error("Unexpected error during XML finalization: {}", e.getMessage(), e);
        }
        return null;
    }
}
