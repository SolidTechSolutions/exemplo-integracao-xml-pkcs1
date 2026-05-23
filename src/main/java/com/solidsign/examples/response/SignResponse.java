package com.solidsign.examples.response;
import java.util.List;
public class SignResponse {
    public String identifier; public int signatureCount; public List<DocumentItem> documents;
    public static class DocumentItem { public String hash; public List<LinkItem> links; }
    public static class LinkItem     { public String rel;  public String href; }
}
