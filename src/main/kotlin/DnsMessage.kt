data class DnsMessage(
    val header: DnsHeader,                           // 12 bytes: Information about the query/response. Contains fields like ID, flags (QR, opcode, AA, TC, RD, RA, Z, RCODE), and counts of questions, answers, authority records, and additional records.
    val questions: List<DnsQuestion> = emptyList(),  // Variable: List of Questions - The questions being asked in the DNS query.
    val answers: List<DnsRecord> = emptyList(),      // Variable: List of Records - The answers to the questions asked. The relevant records of the requested type.
//    val authorities: List<DnsRecord> = emptyList(),  // Variable: The authority records, which provide information about the authoritative name servers for the domain. A list of name servers (NS records), used for resolving queries recursively.
//    val additionals: List<DnsRecord> = emptyList()  // Variable: The additional records, which may include extra information such as IP addresses of the authoritative name servers.
) {
    data class DnsHeader(
        val id: Int = 0,                            // 16 bits: Packet Identifier
        val queryResponse: Boolean = false,         // 1 bit: Query Response (true for response, false for query)
        val operationCode: Int = 0,                 // 4 bits: Operation Code
        val authoritativeAnswer: Boolean = false,   //ß 1 bit: Authoritative Answer
        val truncatedMessage: Boolean = false,      // 1 bit: Truncated Message
        val recursionDesired: Boolean = false,      // 1 bit: Recursion Desired
        val recursionAvailable: Boolean = false,    // 1 bit: Recursion Available
        val reserved: Int = 0,                      // 3 bits: Reserved
        val responseCode: Int = 0,                  // 4 bits: Response Code
        val questionCount: Int = 0,                 // 16 bits: Question Count
        val answerCount: Int = 0,                   // 16 bits: Answer Count
        val authorityCount: Int = 0,                // 16 bits: Authority Count
        val additionalCount: Int = 0                // 16 bits: Additional Count
    )

    data class DnsQuestion(
        val name: String = "",                      // Label Sequence: The domain name being queried, represented as a sequence of labels.
        val type: DnsType = DnsType(),              // 16 bits: Type of the record being queried (e.g., A, AAAA, CNAME, etc.)
        val classCode: DnsClass = DnsClass()        // 16 bits: Class of the record being queried (usually IN for Internet)
    )

    data class DnsRecord(
        val name: String = "",                      // Label Sequence: The domain name associated with the record, represented as a sequence of label
        val type: DnsType = DnsType(),              // 16 bits: Type of the record (e.g., A, AAAA, CNAME, etc.)
        val classCode: DnsClass = DnsClass(),       // 16 bits: Class of the record (usually IN for Internet)
        val ttl: Int = 0,                           // 32 bits: Time to Live - The time in seconds that the record may be cached by resolvers.
        val len: Int = 0,                           // 16 bits: Length of the data field in bytes
        val data: ByteArray                         // Variable: The data field containing the record data, such as an IP address for A records or a domain name for CNAME records.
    )

    data class DnsType(
        val value: Int = 0          // 16 bits: The type of DNS record (e.g., A, AAAA, CNAME, etc.)
    )

    data class DnsClass(
        val value: Int = 0          // 16 bits: The class of DNS record (usually IN for Internet)
    )
}

