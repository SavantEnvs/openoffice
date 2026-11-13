// Known-answer oracle over the same library code the fuzzers exercise (built without sanitizers).
// Run from the repo root; prints "PASS name" / "FAIL name" lines and exits non-zero on any FAIL.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <rtl/string.hxx>
#include <sft.hxx>

#include "pdfparse.hxx"

namespace {

std::vector<char> slurp(const char* path)
{
    std::vector<char> v;
    FILE* f = fopen(path, "rb");
    if (!f)
        return v;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        v.insert(v.end(), buf, buf + n);
    fclose(f);
    return v;
}

class MemEmitContext : public pdfparse::EmitContext
{
    const char* m_pOrig;
    unsigned int m_nOrigLen;

public:
    std::vector<char> m_aOut;
    MemEmitContext(const pdfparse::PDFContainer* pTop, const char* pOrig, unsigned int nOrigLen)
        : pdfparse::EmitContext(pTop), m_pOrig(pOrig), m_nOrigLen(nOrigLen) {}
    virtual bool write(const void* pBuf, unsigned int nLen)
    {
        const char* p = static_cast<const char*>(pBuf);
        m_aOut.insert(m_aOut.end(), p, p + nLen);
        return true;
    }
    virtual unsigned int getCurPos() { return static_cast<unsigned int>(m_aOut.size()); }
    virtual bool copyOrigBytes(unsigned int nOff, unsigned int nLen)
    {
        if (nOff > m_nOrigLen || nLen > m_nOrigLen - nOff)
            return false;
        return write(m_pOrig + nOff, nLen);
    }
    virtual unsigned int readOrigBytes(unsigned int nOff, unsigned int nLen, void* pBuf)
    {
        if (nOff > m_nOrigLen || nLen > m_nOrigLen - nOff)
            return 0;
        memcpy(pBuf, m_pOrig + nOff, nLen);
        return nLen;
    }
};

int g_failed = 0, g_passed = 0;

void check(bool ok, const char* what, long got = 0)
{
    printf("%s %s (%ld)\n", ok ? "PASS" : "FAIL", what, got);
    if (ok) ++g_passed; else ++g_failed;
}

uint64_t fnv(uint64_t h, const std::vector<char>& v)
{
    for (char c : v)
        h = (h ^ static_cast<unsigned char>(c)) * 1099511628211ull;
    return h;
}

struct PdfCase
{
    const char* path;
    long objs, streams, streamBytes, emitted;
    unsigned long long streamHash;
};

void checkPdf(const PdfCase& c)
{
    std::string n = c.path;
    std::vector<char> pdf = slurp(c.path);
    pdfparse::PDFReader aReader;
    pdfparse::PDFEntry* pEntry = aReader.read(pdf.data(), static_cast<unsigned int>(pdf.size()));
    check(pEntry != nullptr, (n + " parses").c_str(), static_cast<long>(pdf.size()));
    if (!pEntry)
        return;
    pdfparse::PDFContainer* pTop = dynamic_cast<pdfparse::PDFContainer*>(pEntry);
    pdfparse::PDFFile* pFile = dynamic_cast<pdfparse::PDFFile*>(pEntry);
    check(pFile != nullptr && pTop != nullptr, (n + " root is a PDFFile").c_str());
    if (!pTop)
    {
        delete pEntry;
        return;
    }
    long nObjs = 0, nStreams = 0, nStreamBytes = 0;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < pTop->m_aSubElements.size(); ++i)
    {
        pdfparse::PDFObject* pObj = dynamic_cast<pdfparse::PDFObject*>(pTop->m_aSubElements[i]);
        if (!pObj)
            continue;
        ++nObjs;
        if (pObj->m_pStream)
        {
            ++nStreams;
            MemEmitContext aCtx(pTop, pdf.data(), static_cast<unsigned int>(pdf.size()));
            aCtx.m_bDeflate = true;
            pObj->writeStream(aCtx, pFile);
            nStreamBytes += static_cast<long>(aCtx.m_aOut.size());
            h = fnv(h, aCtx.m_aOut);
        }
    }
    MemEmitContext aPlain(pTop, pdf.data(), static_cast<unsigned int>(pdf.size()));
    pEntry->emit(aPlain);
    printf("INFO %s stream hash %llu\n", c.path, static_cast<unsigned long long>(h));
    check(nObjs == c.objs, (n + " object count").c_str(), nObjs);
    check(nStreams == c.streams, (n + " stream count").c_str(), nStreams);
    check(nStreamBytes == c.streamBytes, (n + " inflated stream bytes").c_str(), nStreamBytes);
    check(h == c.streamHash, (n + " inflated stream hash").c_str(), static_cast<long>(h & 0x7fffffff));
    check(static_cast<long>(aPlain.m_aOut.size()) == c.emitted, (n + " re-emitted size").c_str(),
          static_cast<long>(aPlain.m_aOut.size()));
    delete pEntry;
}

}

int main()
{
    static const PdfCase aCases[] = {
        {"mayhem/fuzz_pdfparse/testsuite/pictxt.pdf", 15, 4, 50487, 24577, 239407610896191779ull},
        {"mayhem/fuzz_pdfparse/testsuite/verticaltext.pdf", 13, 3, 14875, 16613, 13989396930500456430ull},
    };
    for (const PdfCase& c : aCases)
        checkPdf(c);

    {
        const char junk[] = "this is not a pdf file at all";
        pdfparse::PDFReader aReader;
        pdfparse::PDFEntry* p = aReader.read(junk, sizeof junk - 1);
        pdfparse::PDFContainer* pc = dynamic_cast<pdfparse::PDFContainer*>(p);
        check(p == nullptr || (pc && pc->m_aSubElements.empty()), "junk is not parsed as pdf objects");
        delete p;
    }

    std::vector<char> ttf = slurp("main/extras/source/truetype/symbol/opens___.ttf");
    vcl::TrueTypeFont* font = nullptr;
    int rc = vcl::OpenTTFontBuffer(ttf.data(), static_cast<sal_uInt32>(ttf.size()), 0, &font);
    check(rc == vcl::SF_OK && font, "opens___.ttf opens", rc);
    if (font)
    {
        vcl::TTGlobalFontInfo info;
        memset(&info, 0, sizeof info);
        vcl::GetTTGlobalFontInfo(font, &info);
        check(info.family && strcmp(info.family, "OpenSymbol") == 0, "font family is OpenSymbol");
        check(info.psname && strcmp(info.psname, "OpenSymbol") == 0, "font PostScript name is OpenSymbol");
        check(vcl::GetTTGlyphCount(font) == 1014, "glyph count", vcl::GetTTGlyphCount(font));
        check(info.weight == 400, "weight class", info.weight);
        check(info.xMin == -179 && info.yMin == -312 && info.xMax == 1083 && info.yMax == 916,
              "global bounding box");
        check(info.ascender == 916 && info.descender == -312, "ascender/descender");

        sal_uInt16 ids[4] = {0, 1, 2, 3};
        vcl::TTSimpleGlyphMetrics* m = vcl::GetTTSimpleGlyphMetrics(font, ids, 4, 0);
        check(m && m[0].adv == 365 && m[0].sb == 33 && m[2].adv == 333 && m[3].adv == 500,
              "glyph metrics");
        free(m);

        check(vcl::MapChar(font, 0x2200, 0) == 118 && vcl::MapChar(font, 0x2211, 0) == 129
                  && vcl::MapChar(font, 0x221E, 0) == 136 && vcl::MapChar(font, 0x20, 0) == 5,
              "cmap lookups");

        sal_uInt8 enc[3] = {0, 1, 2};
        sal_uInt16 g[3] = {0, vcl::MapChar(font, 0x2200, 0), vcl::MapChar(font, 0x2211, 0)};
        char* out = nullptr;
        size_t n = 0;
        FILE* f = open_memstream(&out, &n);
        int r = vcl::CreateT42FromTTGlyphs(font, f, "TestFont", g, enc, 3);
        fclose(f);
        check(r == vcl::SF_OK && n == 3468, "type42 subset size", static_cast<long>(n));
        check(out && strstr(out, "/FontName (TestFont) cvn def") != nullptr, "type42 subset carries the requested PostScript name");
        free(out);
        vcl::CloseTTFont(font);
    }

    vcl::TrueTypeFont* bad = nullptr;
    char junk[64];
    memset(junk, 'x', sizeof junk);
    check(vcl::OpenTTFontBuffer(junk, sizeof junk, 0, &bad) != vcl::SF_OK, "junk is not an sfnt");

    printf("TOTAL passed=%d failed=%d\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
