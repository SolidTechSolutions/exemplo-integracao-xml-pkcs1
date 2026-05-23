package com.solidsign.examples.response;
import java.util.List;
/**
 * Maps PreparedHashesDTO from SolidSign sign-preparation.
 * Forward to React frontend — browser extension (eToken A3/A1 certstore) signs each hash.
 */
public class PreparedHashesResponse {
    public String finalNonce; public int hashCount; public List<HashItem> hashes;
    public static class HashItem { public int index; public String hash; }
}
