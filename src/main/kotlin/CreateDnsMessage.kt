fun serializeDnsMessage(message: DnsMessage): ByteArray {
    val headerBytes = serializeDnsHeader(message.header)
    val questionBytes = message.questions.flatMap { serializeDnsQuestion(it).asIterable() }.toByteArray()
    val answerBytes = message.answers.flatMap { serializeDnsRecord(it).asIterable() }.toByteArray()

    return headerBytes + questionBytes + answerBytes
}

fun serializeDnsHeader(header: DnsMessage.DnsHeader): ByteArray {
    val data = ByteArray(12)

    // ID (16 bits) - bytes 0-1
    data[0] = ((header.id shr 8) and 0xFF).toByte()
    data[1] = (header.id and 0xFF).toByte()

    // Flags (16 bits) - bytes 2-3
    var flags = 0
    if (header.queryResponse) flags = flags or (1 shl 15)
    flags = flags or ((header.operationCode and 0b1111) shl 11)
    if (header.authoritativeAnswer) flags = flags or (1 shl 10)
    if (header.truncatedMessage) flags = flags or (1 shl 9)
    if (header.recursionDesired) flags = flags or (1 shl 8)
    if (header.recursionAvailable) flags = flags or (1 shl 7)
    flags = flags or ((header.reserved and 0b111) shl 4)
    flags = flags or (header.responseCode and 0b1111)

    data[2] = ((flags shr 8) and 0xFF).toByte()
    data[3] = (flags and 0xFF).toByte()

    // Question count (16 bits) - bytes 4-5
    data[4] = ((header.questionCount shr 8) and 0xFF).toByte()
    data[5] = (header.questionCount and 0xFF).toByte()

    // Answer count (16 bits) - bytes 6-7
    data[6] = ((header.answerCount shr 8) and 0xFF).toByte()
    data[7] = (header.answerCount and 0xFF).toByte()

    // Authority count (16 bits) - bytes 8-9
    data[8] = ((header.authorityCount shr 8) and 0xFF).toByte()
    data[9] = (header.authorityCount and 0xFF).toByte()

    // Additional count (16 bits) - bytes 10-11
    data[10] = ((header.additionalCount shr 8) and 0xFF).toByte()
    data[11] = (header.additionalCount and 0xFF).toByte()

    return data
}

fun serializeDnsQuestion(question: DnsMessage.DnsQuestion): ByteArray {
    val nameBytes = encodeDomainName(question.name)
    val typeBytes = byteArrayOf(
        ((question.type.value shr 8) and 0xFF).toByte(),
        (question.type.value and 0xFF).toByte()
    )
    val classBytes = byteArrayOf(
        ((question.classCode.value shr 8) and 0xFF).toByte(),
        (question.classCode.value and 0xFF).toByte()
    )

    return nameBytes + typeBytes + classBytes
}

fun serializeDnsRecord(record: DnsMessage.DnsRecord): ByteArray {
    val nameBytes = encodeDomainName(record.name)
    val typeBytes = byteArrayOf(
        ((record.type.value shr 8) and 0xFF).toByte(),
        (record.type.value and 0xFF).toByte()
    )
    val classBytes = byteArrayOf(
        ((record.classCode.value shr 8) and 0xFF).toByte(),
        (record.classCode.value and 0xFF).toByte()
    )
    val ttlBytes = byteArrayOf(
        ((record.ttl shr 24) and 0xFF).toByte(),
        ((record.ttl shr 16) and 0xFF).toByte(),
        ((record.ttl shr 8) and 0xFF).toByte(),
        (record.ttl and 0xFF).toByte()
    )
    val lengthBytes = byteArrayOf(
        ((record.len shr 8) and 0xFF).toByte(),
        (record.len and 0xFF).toByte()
    )

    return nameBytes + typeBytes + classBytes + ttlBytes + lengthBytes + record.data
}

fun encodeDomainName(domain: String): ByteArray {
    if (domain.isEmpty()) return byteArrayOf(0)

    val result = mutableListOf<Byte>()
    val labels = domain.split('.')

    for (label in labels) {
        if (label.isNotEmpty()) {
            result.add(label.length.toByte())
            result.addAll(label.toByteArray().toList())
        }
    }
    result.add(0) // Null terminator

    return result.toByteArray()
}