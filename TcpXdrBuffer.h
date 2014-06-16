#ifndef TCP_XDR_BUFFER_H
#define TCP_XDR_BUFFER_H
class TcpXdrBuffer
{
public:
    uint8_t *data;
    unsigned int start;
    unsigned int end;
    TcpXdrBuffer(void);
    ~TcpXdrBuffer(void);
    void add(uint8_t*, unsigned int, unsigned int);
    void remove(unsigned int);
    unsigned int xdr_size() const;
    uint8_t* get_xdr(unsigned int&, bool= 0);
    void panic(unsigned int);
    static const unsigned int xdr_type_offset= 0;
    static const unsigned int xdr_size_offset= 4;
    static const unsigned int xdr_hdr_size= 8;
    static const unsigned int xdr_size_max= 10000;
    static const unsigned int xdr_type_max= 11;
private:
     TcpXdrBuffer& operator=(const TcpXdrBuffer &); //assignment
     TcpXdrBuffer(const TcpXdrBuffer &); //copy constructor
};
#endif // TCP_XDR_BUFFER_H
