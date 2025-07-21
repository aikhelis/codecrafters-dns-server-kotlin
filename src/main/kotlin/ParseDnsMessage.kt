fun parseDnsHeader(data: ByteArray): DnsMessage.DnsHeader {
    if (data.size < 12) {
        throw IllegalArgumentException("DNS header requires at least 12 bytes, got ${data.size}")
    }

    val id = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
    val flags = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
    val queryResponse = (flags shr 15) and 1 == 1
    val operationCode = (flags shr 11) and 0b1111
    val authoritativeAnswer = (flags shr 10) and 1 == 1
    val truncatedMessage = (flags shr 9) and 1 == 1
    val recursionDesired = (flags shr 8) and 1 == 1
    val recursionAvailable = (flags shr 7) and 1 == 1
    val reserved = (flags shr 4) and 0b111
    val responseCode = flags and 0b1111
    val questionCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
    val answerCount = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
    val authorityCount = ((data[8].toInt() and 0xFF) shl 8) or (data[9].toInt() and 0xFF)
    val additionalCount = ((data[10].toInt() and 0xFF) shl 8) or (data[11].toInt() and 0xFF)

    return DnsMessage.DnsHeader(
        id = id,
        queryResponse = queryResponse,
        operationCode = operationCode,
        authoritativeAnswer = authoritativeAnswer,
        truncatedMessage = truncatedMessage,
        recursionDesired = recursionDesired,
        recursionAvailable = recursionAvailable,
        reserved = reserved,
        responseCode = responseCode,
        questionCount = questionCount,
        answerCount = answerCount,
        authorityCount = authorityCount,
        additionalCount = additionalCount
    )
}

fun parseDnsQuestion(data: ByteArray, offset: Int): Pair<DnsMessage.DnsQuestion, Int> {
    // Parse domain name
    val (domainName, nameEndOffset) = parseDomainName(data, offset)

    // Parse type (2 bytes)
    val type = ((data[nameEndOffset].toInt() and 0xFF) shl 8) or (data[nameEndOffset + 1].toInt() and 0xFF)

    // Parse class (2 bytes)
    val classCode = ((data[nameEndOffset + 2].toInt() and 0xFF) shl 8) or (data[nameEndOffset + 3].toInt() and 0xFF)

    val question = DnsMessage.DnsQuestion(
        name = domainName,
        type = DnsMessage.DnsType(type),
        classCode = DnsMessage.DnsClass(classCode)
    )

    return Pair(question, nameEndOffset + 4)
}

fun parseDnsRecord(data: ByteArray, offset: Int): Pair<DnsMessage.DnsRecord, Int> {
    // Parse domain name
    val (domainName, nameEndOffset) = parseDomainName(data, offset)

    // Parse type (2 bytes)
    val type = ((data[nameEndOffset].toInt() and 0xFF) shl 8) or (data[nameEndOffset + 1].toInt() and 0xFF)

    // Parse class (2 bytes)
    val classCode = ((data[nameEndOffset + 2].toInt() and 0xFF) shl 8) or (data[nameEndOffset + 3].toInt() and 0xFF)

    // Parse TTL (4 bytes)
    val ttl = ((data[nameEndOffset + 4].toInt() and 0xFF) shl 24) or
              ((data[nameEndOffset + 5].toInt() and 0xFF) shl 16) or
              ((data[nameEndOffset + 6].toInt() and 0xFF) shl 8) or
              (data[nameEndOffset + 7].toInt() and 0xFF)

    // Parse data length (2 bytes)
    val dataLength = ((data[nameEndOffset + 8].toInt() and 0xFF) shl 8) or (data[nameEndOffset + 9].toInt() and 0xFF)

    // Parse data
    val recordData = data.copyOfRange(nameEndOffset + 10, nameEndOffset + 10 + dataLength)

    val record = DnsMessage.DnsRecord(
        name = domainName,
        type = DnsMessage.DnsType(type),
        classCode = DnsMessage.DnsClass(classCode),
        ttl = ttl,
        len = dataLength,
        data = recordData
    )

    return Pair(record, nameEndOffset + 10 + dataLength)
}

// Parses a domain name from a byte array starting at the given offset. Decodes labels and handles compression pointers.
fun parseDomainName(data: ByteArray, offset: Int): Pair<String, Int> {
    val labels = mutableListOf<String>()
    var currentOffset = offset
    var jumped = false
    var jumpedOffset = -1

    while (currentOffset < data.size) {
        val labelLength = data[currentOffset].toInt() and 0xFF

        if (labelLength == 0) {
            // End of domain name
            currentOffset++
            break
        }

        // Check if this is a compression pointer (first two bits are 11)
        if ((labelLength and 0xC0) == 0xC0) {
            // This is a compression pointer
            if (!jumped) {
                // Save our current position to return after following the pointer
                jumpedOffset = currentOffset + 2
                jumped = true
            }

            // Extract the 14-bit offset from the pointer
            val pointer = ((labelLength and 0x3F) shl 8) or (data[currentOffset + 1].toInt() and 0xFF)
            currentOffset = pointer
            continue
        }

        if (labelLength > 63) {
            throw IllegalArgumentException("Invalid label length: $labelLength")
        }

        currentOffset++
        val label = String(data, currentOffset, labelLength)
        labels.add(label)
        currentOffset += labelLength
    }

    // If we jumped to follow a pointer, return the position after the pointer
    val finalOffset = if (jumped) jumpedOffset else currentOffset
    return Pair(labels.joinToString("."), finalOffset)
}

fun parseDnsMessageWithoutAnswers(data: ByteArray): DnsMessage {
    val header = parseDnsHeader(data)
    val questions = mutableListOf<DnsMessage.DnsQuestion>()

    var offset = 12 // Skip header

    // Parse questions
    repeat(header.questionCount) {
        val (question, newOffset) = parseDnsQuestion(data, offset)
        questions.add(question)
        offset = newOffset
    }

    return DnsMessage(
        header = header,
        questions = questions
    )
}

fun parseDnsMessageWithAnswers(data: ByteArray): DnsMessage {
    val header = parseDnsHeader(data)
    val questions = mutableListOf<DnsMessage.DnsQuestion>()
    val answers = mutableListOf<DnsMessage.DnsRecord>()

    var offset = 12 // Skip header

    // Parse questions
    repeat(header.questionCount) {
        val (question, newOffset) = parseDnsQuestion(data, offset)
        questions.add(question)
        offset = newOffset
    }

    // Parse answers
    repeat(header.answerCount) {
        val (answer, newOffset) = parseDnsRecord(data, offset)
        answers.add(answer)
        offset = newOffset
    }

    return DnsMessage(
        header = header,
        questions = questions,
        answers = answers
    )
}
