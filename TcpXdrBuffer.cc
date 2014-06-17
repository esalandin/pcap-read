#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "TcpXdrBuffer.h"

TcpXdrBuffer::TcpXdrBuffer()
{
    data= NULL;
    start= end= 0;
}

TcpXdrBuffer::~TcpXdrBuffer()
{
    free(data);
}

TcpXdrBuffer::TcpXdrBuffer(const TcpXdrBuffer &rhs)
{
	if (rhs.start==rhs.end)
    {
        data= NULL;
        return;
    }
    start= 0;
    end= rhs.end - rhs.start;
    data= static_cast<uint8_t *>( malloc(end-start));
    memcpy(data, rhs.data+rhs.start, end-start);
}

void TcpXdrBuffer::add(uint8_t *newdata_ptr, unsigned int newdata_len, unsigned int packet_no)
{
    if (start==end && end!=0)
        {
        free(data);
        data= NULL;
        start= end= 0;
        }

    if (newdata_ptr==NULL || newdata_len == 0)
        {
        return;
        }

    data= static_cast<uint8_t*>(realloc(data, end+newdata_len));
    memcpy(data+end, newdata_ptr, newdata_len);
    end += newdata_len;

    uint8_t *xdr_hdr= data+start;
    if (xdr_size() > xdr_size_max)
        {
        panic(packet_no);
        return;
        }
    if (end - start > xdr_size_max)
        {
        panic(packet_no);
        return;
        }
    if (xdr_hdr[xdr_type_offset] > xdr_type_max)
        {
        panic(packet_no);
        return;
        }
}

void TcpXdrBuffer::remove(unsigned int size)
{
    if (end < start + size)
        {
        panic(0);
        return;
        }
    start += size;
    return;
}

unsigned int TcpXdrBuffer::xdr_size() const
{
    if (end-start<xdr_hdr_size)
        {
        return 0;
        }
    unsigned int size= 0;
    uint8_t *xdr_header= data+start;
    for (int i=0; i<4; ++i)
        {
        size = (size << 8) + xdr_header[xdr_size_offset+i];
        }
    return size;
}

uint8_t* TcpXdrBuffer::get_xdr(unsigned int &xdr_size_out, bool want_remove)
{
    if (end == start)
        {
        xdr_size_out= 0;
        return NULL;
        }
    unsigned int xdr_sz= xdr_size();
    if (end-start < xdr_hdr_size+xdr_sz)
        {
        // we don't have enough data yet
        xdr_size_out= 0;
        return NULL;
        }
    uint8_t *xdr_ptr= data + start;
    xdr_size_out= xdr_hdr_size+xdr_sz;

    if (want_remove)
        {
        remove(xdr_hdr_size+xdr_sz);
        }

    return xdr_ptr;
}

void TcpXdrBuffer::panic(unsigned int packet_number)
{
    fprintf(stderr, "TcpXdrBuffer panic: ");
    fprintf(stderr, "packet_number= %u; buffer start= %u; buffer end= %u; buffer size= %d; ", packet_number, start, end, end-start);
    uint8_t *xdr_hdr= data+start;
    for (unsigned int i=0; i<xdr_hdr_size;++i)
        fprintf(stderr, "%02X ", xdr_hdr[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
    free(data);
    data= NULL;
    start= end= 0;
}
