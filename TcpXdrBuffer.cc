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
    delete[] data;
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
    data= new uint8_t[end-start];
    memcpy(data, rhs.data+rhs.start, end-start);
}

void TcpXdrBuffer::add(uint8_t *newdata_ptr, unsigned int newdata_len, unsigned int packet_no)
{
    // we do all memory move operations here, so we can use memory returned by get_xdr
    if (start>end)
        {
        // oops
        panic(0);
        return;
        }

    if (start==end && end!=0)
        {
        // empty, free up all
        delete[] data;
        data= NULL;
        start= end= 0;
        }

    if (newdata_ptr==NULL || newdata_len == 0)
        {
        // nothing to do
        return;
        }

    unsigned int new_start= 0;
    unsigned int new_end= (end-start+newdata_len);
    uint8_t *new_data= new uint8_t[new_end];
    memcpy(new_data+new_start, data+start, end-start);
    memcpy(new_data+new_start+end-start, newdata_ptr, newdata_len);

    delete[] data;
    data= new_data;
    start= new_start;
    end= new_end;

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
    delete[] data;
    data= NULL;
    start= end= 0;
}
