package com.webshield.api.reporting.pdf;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight, zero-dependency, spec-compliant PDF 1.4 document builder.
 * Generates structured documents with cover banners, running headers/footers,
 * page numbers, tables, colored boxes, word-wrapped text, and code blocks.
 */
public class SimplePdfWriter {

    public static final float PAGE_WIDTH = 595.28f;  // A4 Width in points (72 DPI)
    public static final float PAGE_HEIGHT = 841.89f; // A4 Height in points
    public static final float MARGIN = 40.0f;
    public static final float CONTENT_WIDTH = PAGE_WIDTH - (2 * MARGIN);

    private final List<PageContent> pages = new ArrayList<>();
    private PageContent currentPage;

    public SimplePdfWriter() {
        newPage();
    }

    public static class PageContent {
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        float currentY = PAGE_HEIGHT - MARGIN - 30.0f; // leave room for running header
    }

    public void newPage() {
        currentPage = new PageContent();
        pages.add(currentPage);
    }

    public int getPageCount() {
        return pages.size();
    }

    public float getCurrentY() {
        return currentPage.currentY;
    }

    public void checkPageSpace(float requiredHeight) {
        if (currentPage.currentY - requiredHeight < MARGIN + 35.0f) { // leave room for footer
            newPage();
        }
    }

    public void drawRect(float x, float y, float width, float height, float r, float g, float b, boolean fill) {
        String cmd = String.format(java.util.Locale.US, "%.2f %.2f %.2f %s %.2f %.2f %.2f %.2f re %s\n",
                r, g, b, fill ? "rg" : "RG",
                x, y, width, height,
                fill ? "f" : "s");
        writeRaw(cmd);
    }

    public void drawLine(float x1, float y1, float x2, float y2, float r, float g, float b, float lineWidth) {
        String cmd = String.format(java.util.Locale.US, "%.2f w %.2f %.2f %.2f RG %.2f %.2f m %.2f %.2f l S\n",
                lineWidth, r, g, b, x1, y1, x2, y2);
        writeRaw(cmd);
    }

    public void addText(String text, float x, float y, String fontTag, float fontSize, float r, float g, float b) {
        if (text == null) return;
        String safe = escapePdfText(text);
        String cmd = String.format(java.util.Locale.US, "BT /%s %.2f Tf %.2f %.2f %.2f rg %.2f %.2f Td (%s) Tj ET\n",
                fontTag, fontSize, r, g, b, x, y, safe);
        writeRaw(cmd);
    }

    public void addParagraph(String text, float x, String fontTag, float fontSize, float r, float g, float b, float width) {
        if (text == null || text.isBlank()) return;
        List<String> lines = wrapText(text, fontSize, width);
        float lineHeight = fontSize * 1.35f;

        for (String line : lines) {
            checkPageSpace(lineHeight);
            addText(line, x, currentPage.currentY, fontTag, fontSize, r, g, b);
            currentPage.currentY -= lineHeight;
        }
    }

    public void addSectionTitle(String title) {
        checkPageSpace(45.0f);
        currentPage.currentY -= 15.0f;
        addText(title, MARGIN, currentPage.currentY, "F2", 14.0f, 0.09f, 0.14f, 0.22f); // #172338
        drawLine(MARGIN, currentPage.currentY - 4.0f, MARGIN + CONTENT_WIDTH, currentPage.currentY - 4.0f, 0.21f, 0.42f, 0.90f, 1.5f); // #356AE6
        currentPage.currentY -= 18.0f;
    }

    public void addSubSectionTitle(String title) {
        checkPageSpace(30.0f);
        currentPage.currentY -= 10.0f;
        addText(title, MARGIN, currentPage.currentY, "F2", 11.5f, 0.15f, 0.20f, 0.30f);
        currentPage.currentY -= 15.0f;
    }

    public void addCodeBlock(String code, float x, float width) {
        if (code == null || code.isBlank()) return;
        String[] lines = code.split("\\r?\\n");
        float fontSize = 8.5f;
        float lineHeight = 11.0f;
        int maxLines = Math.min(lines.length, 12);
        float boxHeight = (maxLines * lineHeight) + 12.0f;

        checkPageSpace(boxHeight + 5.0f);
        drawRect(x, currentPage.currentY - boxHeight + 4.0f, width, boxHeight, 0.06f, 0.09f, 0.16f, true); // #0F172A

        float lineY = currentPage.currentY - 10.0f;
        for (int i = 0; i < maxLines; i++) {
            String l = lines[i].length() > 85 ? lines[i].substring(0, 82) + "..." : lines[i];
            addText(l, x + 8.0f, lineY, "F3", fontSize, 0.22f, 0.74f, 0.97f); // #38BDF8
            lineY -= lineHeight;
        }
        currentPage.currentY -= (boxHeight + 8.0f);
    }

    public void addCalloutBox(String title, String content, float r, float g, float b) {
        List<String> lines = wrapText(content, 9.0f, CONTENT_WIDTH - 20.0f);
        float height = (lines.size() * 12.0f) + 28.0f;
        checkPageSpace(height);

        // Background light tint and left accent bar
        drawRect(MARGIN, currentPage.currentY - height, CONTENT_WIDTH, height, 0.97f, 0.98f, 0.99f, true);
        drawRect(MARGIN, currentPage.currentY - height, 4.0f, height, r, g, b, true);
        drawRect(MARGIN, currentPage.currentY - height, CONTENT_WIDTH, height, 0.88f, 0.91f, 0.94f, false);

        float textY = currentPage.currentY - 14.0f;
        addText(title, MARGIN + 12.0f, textY, "F2", 9.5f, r, g, b);
        textY -= 14.0f;
        for (String line : lines) {
            addText(line, MARGIN + 12.0f, textY, "F1", 8.5f, 0.20f, 0.25f, 0.35f);
            textY -= 12.0f;
        }
        currentPage.currentY -= (height + 10.0f);
    }

    public void addTable(String[] headers, float[] colWidths, List<String[]> rows) {
        float tableWidth = 0;
        for (float w : colWidths) tableWidth += w;
        float rowHeight = 18.0f;

        checkPageSpace(rowHeight * 2);

        // Header Row
        drawRect(MARGIN, currentPage.currentY - rowHeight, tableWidth, rowHeight, 0.94f, 0.96f, 0.98f, true);
        drawRect(MARGIN, currentPage.currentY - rowHeight, tableWidth, rowHeight, 0.85f, 0.88f, 0.92f, false);

        float curX = MARGIN;
        for (int i = 0; i < headers.length; i++) {
            addText(headers[i], curX + 6.0f, currentPage.currentY - 12.0f, "F2", 8.5f, 0.15f, 0.20f, 0.30f);
            curX += colWidths[i];
        }
        currentPage.currentY -= rowHeight;

        // Data Rows
        boolean alternate = false;
        for (String[] row : rows) {
            checkPageSpace(rowHeight);
            if (alternate) {
                drawRect(MARGIN, currentPage.currentY - rowHeight, tableWidth, rowHeight, 0.98f, 0.99f, 1.0f, true);
            }
            drawRect(MARGIN, currentPage.currentY - rowHeight, tableWidth, rowHeight, 0.90f, 0.92f, 0.95f, false);

            curX = MARGIN;
            for (int i = 0; i < Math.min(row.length, colWidths.length); i++) {
                String val = row[i] != null ? row[i] : "";
                if (val.length() > 45) val = val.substring(0, 42) + "...";
                addText(val, curX + 6.0f, currentPage.currentY - 12.0f, "F1", 8.0f, 0.20f, 0.25f, 0.35f);
                curX += colWidths[i];
            }
            currentPage.currentY -= rowHeight;
            alternate = !alternate;
        }
        currentPage.currentY -= 8.0f;
    }

    public void writeTo(OutputStream out) throws IOException {
        int totalPages = pages.size();

        // Inject Running Headers & Footers into each page (except Cover Page)
        for (int i = 0; i < totalPages; i++) {
            PageContent p = pages.get(i);
            ByteArrayOutputStream bos = p.stream;
            if (i > 0) { // skip header/footer on cover
                // Running Header
                String hStr = String.format(java.util.Locale.US,
                        "BT /F1 8.00 Tf 0.45 0.50 0.58 rg %.2f %.2f Td (WebShield API Security Assessment Report) Tj ET\n" +
                        "0.50 w 0.85 0.88 0.92 RG %.2f %.2f m %.2f %.2f l S\n",
                        MARGIN, PAGE_HEIGHT - MARGIN + 4.0f,
                        MARGIN, PAGE_HEIGHT - MARGIN, MARGIN + CONTENT_WIDTH, PAGE_HEIGHT - MARGIN);
                bos.write(hStr.getBytes(StandardCharsets.US_ASCII));

                // Running Footer with page numbering
                String pageNum = "Page " + (i + 1) + " of " + totalPages;
                String fStr = String.format(java.util.Locale.US,
                        "0.50 w 0.85 0.88 0.92 RG %.2f %.2f m %.2f %.2f l S\n" +
                        "BT /F1 8.00 Tf 0.50 0.55 0.60 rg %.2f %.2f Td (CONFIDENTIAL - FOR AUTHORIZED USE ONLY) Tj ET\n" +
                        "BT /F2 8.00 Tf 0.21 0.42 0.90 rg %.2f %.2f Td (%s) Tj ET\n",
                        MARGIN, MARGIN + 12.0f, MARGIN + CONTENT_WIDTH, MARGIN + 12.0f,
                        MARGIN, MARGIN + 2.0f,
                        PAGE_WIDTH - MARGIN - 60.0f, MARGIN + 2.0f, pageNum);
                bos.write(fStr.getBytes(StandardCharsets.US_ASCII));
            }
        }

        // Write PDF file structure
        List<Long> offsets = new ArrayList<>();
        CountingOutputStream cos = new CountingOutputStream(out);

        cos.write("%PDF-1.4\n%\u00E2\u00E3\u00CF\u00D3\n".getBytes(StandardCharsets.ISO_8859_1));

        // Obj 1: Catalog
        offsets.add(cos.getCount());
        cos.write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

        // Obj 2: Pages Tree
        StringBuilder kids = new StringBuilder();
        for (int i = 0; i < totalPages; i++) {
            kids.append((4 + i * 2)).append(" 0 R ");
        }
        offsets.add(cos.getCount());
        String pagesObj = String.format("2 0 obj\n<< /Type /Pages /Kids [ %s] /Count %d >>\nendobj\n", kids, totalPages);
        cos.write(pagesObj.getBytes(StandardCharsets.US_ASCII));

        // Obj 3: Shared Fonts Dictionary
        offsets.add(cos.getCount());
        String fontsObj = "3 0 obj\n<< /Font << " +
                "/F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> " +
                "/F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> " +
                "/F3 << /Type /Font /Subtype /Type1 /BaseFont /Courier >> >> >>\nendobj\n";
        cos.write(fontsObj.getBytes(StandardCharsets.US_ASCII));

        // Write Page Objects & Content Streams
        for (int i = 0; i < totalPages; i++) {
            PageContent p = pages.get(i);
            int pageObjNum = 4 + (i * 2);
            int contentObjNum = pageObjNum + 1;

            // Page Object
            offsets.add(cos.getCount());
            String pStr = String.format(java.util.Locale.US,
                    "%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 %.2f %.2f ] /Resources 3 0 R /Contents %d 0 R >>\nendobj\n",
                    pageObjNum, PAGE_WIDTH, PAGE_HEIGHT, contentObjNum);
            cos.write(pStr.getBytes(StandardCharsets.US_ASCII));

            // Content Stream Object
            offsets.add(cos.getCount());
            byte[] streamBytes = p.stream.toByteArray();
            String cHeader = String.format("%d 0 obj\n<< /Length %d >>\nstream\n", contentObjNum, streamBytes.length);
            cos.write(cHeader.getBytes(StandardCharsets.US_ASCII));
            cos.write(streamBytes);
            cos.write("\nendstream\nendobj\n".getBytes(StandardCharsets.US_ASCII));
        }

        // Cross Reference Table
        long xrefOffset = cos.getCount();
        cos.write(String.format("xref\n0 %d\n0000000000 65535 f \n", offsets.size() + 1).getBytes(StandardCharsets.US_ASCII));
        for (Long offset : offsets) {
            cos.write(String.format(java.util.Locale.US, "%010d 00000 n \n", offset).getBytes(StandardCharsets.US_ASCII));
        }

        // Trailer
        String trailer = String.format(java.util.Locale.US,
                "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
                offsets.size() + 1, xrefOffset);
        cos.write(trailer.getBytes(StandardCharsets.US_ASCII));
        cos.flush();
    }

    private void writeRaw(String cmd) {
        try {
            currentPage.stream.write(cmd.getBytes(StandardCharsets.ISO_8859_1));
        } catch (IOException e) {
            throw new RuntimeException("Error writing PDF command stream", e);
        }
    }

    private String escapePdfText(String text) {
        return text.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replaceAll("[^\\x20-\\x7E]", "?"); // ensure standard ASCII encoding
    }

    private List<String> wrapText(String text, float fontSize, float maxWidth) {
        List<String> result = new ArrayList<>();
        if (text == null) return result;

        // Approximate character width for Helvetica
        float charWidth = fontSize * 0.52f;
        int maxCharsPerLine = Math.max(10, (int) (maxWidth / charWidth));

        String[] paragraphs = text.split("\\r?\\n");
        for (String p : paragraphs) {
            String[] words = p.split("\\s+");
            StringBuilder currentLine = new StringBuilder();

            for (String word : words) {
                if (currentLine.length() + word.length() + 1 > maxCharsPerLine) {
                    if (!currentLine.isEmpty()) {
                        result.add(currentLine.toString());
                        currentLine = new StringBuilder();
                    }
                }
                if (!currentLine.isEmpty()) currentLine.append(" ");
                currentLine.append(word);
            }
            if (!currentLine.isEmpty()) {
                result.add(currentLine.toString());
            }
        }
        return result;
    }

    private static class CountingOutputStream extends FilterOutputStream {
        private long count = 0;

        public CountingOutputStream(OutputStream out) {
            super(out);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            count += len;
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
            count++;
        }

        public long getCount() {
            return count;
        }
    }
}

