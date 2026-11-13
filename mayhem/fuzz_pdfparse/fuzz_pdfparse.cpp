// Fuzz harness for AOO's PDF object parser (sdext/source/pdfimport/pdfparse):
// parse an in-memory PDF, then re-emit it (plain, deflated, decrypted) and
// extract every object's stream, which exercises getDeflatedStream/decrypt.
#include <cstdint>
#include <cstring>
#include <vector>

#include <rtl/string.hxx>

#include "pdfparse.hxx"

namespace {

class MemEmitContext : public pdfparse::EmitContext
{
    const char* m_pOrig;
    unsigned int m_nOrigLen;
    std::vector<char> m_aOut;

public:
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

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    pdfparse::PDFReader aReader;
    pdfparse::PDFEntry* pEntry = aReader.read(reinterpret_cast<const char*>(data),
                                              static_cast<unsigned int>(size));
    if (!pEntry)
        return -1;

    pdfparse::PDFContainer* pTop = dynamic_cast<pdfparse::PDFContainer*>(pEntry);
    pdfparse::PDFFile* pFile = dynamic_cast<pdfparse::PDFFile*>(pEntry);
    const char* pOrig = reinterpret_cast<const char*>(data);
    unsigned int nLen = static_cast<unsigned int>(size);

    {
        MemEmitContext aPlain(pTop, pOrig, nLen);
        pEntry->emit(aPlain);
    }
    {
        MemEmitContext aDeflate(pTop, pOrig, nLen);
        aDeflate.m_bDeflate = true;
        pEntry->emit(aDeflate);
    }
    if (pFile && pFile->isEncrypted())
    {
        if (pFile->setupDecryptionData(rtl::OString()))
        {
            MemEmitContext aDecrypt(pTop, pOrig, nLen);
            aDecrypt.m_bDeflate = true;
            aDecrypt.m_bDecrypt = true;
            pEntry->emit(aDecrypt);
        }
    }
    if (pTop)
    {
        for (size_t i = 0; i < pTop->m_aSubElements.size(); ++i)
        {
            pdfparse::PDFObject* pObj = dynamic_cast<pdfparse::PDFObject*>(pTop->m_aSubElements[i]);
            if (pObj && pObj->m_pStream)
            {
                MemEmitContext aStream(pTop, pOrig, nLen);
                pObj->writeStream(aStream, pFile);
            }
        }
    }

    delete pEntry;
    return 0;
}
