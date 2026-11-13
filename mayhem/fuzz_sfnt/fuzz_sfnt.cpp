// Fuzz harness for AOO's TrueType/OpenType reader and subsetter (vcl/source/fontsubset/sft.cxx):
// open an in-memory sfnt, query its tables, then subset it to Type 42 and to a TrueType file.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

#include <sft.hxx>

using namespace vcl;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 12 || size > (4u << 20))
        return -1;

    std::vector<uint8_t> aBuf(data, data + size);
    TrueTypeFont* ttf = nullptr;
    if (OpenTTFontBuffer(aBuf.data(), static_cast<sal_uInt32>(aBuf.size()), 0, &ttf) != SF_OK || !ttf)
        return -1;

    TTGlobalFontInfo aInfo;
    memset(&aInfo, 0, sizeof(aInfo));
    GetTTGlobalFontInfo(ttf, &aInfo);

    NameRecord* pNames = nullptr;
    int nNames = GetTTNameRecords(ttf, &pNames);

    int nGlyphs = GetTTGlyphCount(ttf);
    if (nGlyphs > 0)
    {
        sal_uInt16 aIds[8];
        sal_uInt8 aEnc[8];
        int nUse = nGlyphs < 8 ? nGlyphs : 8;
        for (int i = 0; i < nUse; ++i)
        {
            aIds[i] = static_cast<sal_uInt16>(i * (nGlyphs / nUse));
            aEnc[i] = static_cast<sal_uInt8>(i);
        }

        for (int i = 0; i < nUse; ++i)
        {
            ControlPoint* pPts = nullptr;
            int n = GetTTGlyphPoints(ttf, aIds[i], &pPts);
            (void)n;
            free(pPts);
            std::vector<sal_uInt32> aComps;
            GetTTGlyphComponents(ttf, aIds[i], aComps);
        }

        free(GetTTSimpleGlyphMetrics(ttf, aIds, nUse, 0));
        free(GetTTSimpleGlyphMetrics(ttf, aIds, nUse, 1));

        const sal_uInt16 nMaxChar = 0x3000;
        for (sal_uInt16 c = 0x20; c < nMaxChar; c = static_cast<sal_uInt16>(c + 0x97))
            MapChar(ttf, c, (c & 1) != 0);
        free(GetTTSimpleCharMetrics(ttf, 0x20, 16, 0));

        {
            char* pOut = nullptr;
            size_t nOut = 0;
            FILE* f = open_memstream(&pOut, &nOut);
            if (f)
            {
                CreateT42FromTTGlyphs(ttf, f, "FuzzFont", aIds, aEnc, nUse);
                fclose(f);
                free(pOut);
            }
        }
        {
            const char* pTmp = getenv("TMPDIR");
            std::string aName = std::string(pTmp && *pTmp ? pTmp : "/tmp") + "/fuzz_sfnt_XXXXXX";
            int fd = mkstemp(&aName[0]);
            if (fd >= 0)
            {
                close(fd);
                CreateTTFromTTGlyphs(ttf, aName.c_str(), aIds, aEnc, nUse, 0, nullptr, 0);
                unlink(aName.c_str());
            }
        }
    }
    if (pNames)
        DisposeNameRecords(pNames, nNames);
    CloseTTFont(ttf);
    return 0;
}
