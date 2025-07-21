import java.net.*

fun main(args: Array<String>) {
    System.err.println("Logs from your program will appear here!")

    // Parse command line arguments for resolver address
    val (resolverAddress: String?, resolverPort: Int) = parseResolverAddress(args)

    val udpSocket = DatagramSocket(2053)

    while (true) {
        val buffer = ByteArray(512)
        val packet = DatagramPacket(buffer, buffer.size)
        udpSocket.receive(packet)

        System.err.println("Received data from ${packet.address}:${packet.port} with length ${packet.length}")

        // Parse the complete DNS message from the received packet
        val queryMessage = parseDnsMessageWithoutAnswers(packet.data.copyOfRange(0, packet.length))
        System.err.println("Received Message: $queryMessage")

        val responseMessage = if (resolverAddress != null) {
            // Forward to resolver
            forwardDnsQuery(queryMessage, resolverAddress, resolverPort)
        } else {
            // Create local response (fallback behavior)
            createDnsReply(queryMessage.header, queryMessage.questions)
        }

        System.err.println("Response Message: $responseMessage")
        val responseBytes = serializeDnsMessage(responseMessage)

        val responsePacket = DatagramPacket(responseBytes, responseBytes.size, packet.address, packet.port)
        udpSocket.send(responsePacket)
    }
}

fun parseResolverAddress(args: Array<String>): Pair<String?, Int> {
    var resolverAddress: String? = null
    var resolverPort = 53 // Default DNS port

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--resolver" -> {
                if (i + 1 < args.size) {
                    val resolverInfo = args[i + 1]
                    val parts = resolverInfo.split(":")
                    resolverAddress = parts[0]
                    if (parts.size > 1) {
                        resolverPort = parts[1].toInt()
                    }
                    i += 2
                } else {
                    System.err.println("Error: --resolver requires an address argument")
                    break
                }
            }
            else -> i++
        }
    }
    return Pair(resolverAddress, resolverPort)
}

fun forwardDnsQuery(originalQuery: DnsMessage, resolverAddress: String, resolverPort: Int): DnsMessage {
    val resolverSocket = DatagramSocket()
    val allAnswers = mutableListOf<DnsMessage.DnsRecord>()

    try {
        // If there are multiple questions, split them into separate queries
        for (question in originalQuery.questions) {
            // Create a single-question query for each question
            val singleQuestionQuery = DnsMessage(
                header = originalQuery.header.copy(
                    questionCount = 1,
                    answerCount = 0,
                    authorityCount = 0,
                    additionalCount = 0
                ),
                questions = listOf(question)
            )

            // Serialize and send the query
            val queryBytes = serializeDnsMessage(singleQuestionQuery)
            val queryPacket = DatagramPacket(
                queryBytes,
                queryBytes.size,
                InetAddress.getByName(resolverAddress),
                resolverPort
            )

            resolverSocket.send(queryPacket)
            System.err.println("Forwarded query for ${question.name} to $resolverAddress:$resolverPort: $singleQuestionQuery")

            // Receive the response
            val responseBuffer = ByteArray(512)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            resolverSocket.receive(responsePacket)

            // Parse the response
            val response = parseDnsMessageWithAnswers(responsePacket.data.copyOfRange(0, responsePacket.length))
            System.err.println("Received response from resolver: $response")

            // Collect answers from this response
            allAnswers.addAll(response.answers)
        }

        // Create the final response with all answers
        return DnsMessage(
            header = originalQuery.header.copy(
                queryResponse = true,
                authoritativeAnswer = false,
                truncatedMessage = false,
                recursionAvailable = false,
                reserved = 0,
                responseCode = if (originalQuery.header.operationCode == 0) 0 else 4, // Set RCODE based on OPCODE: 0 if OPCODE is 0 (standard query), else 4 (not implemented)
                questionCount = originalQuery.questions.size,
                answerCount = allAnswers.size,
                authorityCount = 0,
                additionalCount = 0
            ),
            questions = originalQuery.questions,
            answers = allAnswers
        )

    } catch (e: Exception) {
        System.err.println("Error forwarding DNS query: ${e.message}")
        // Return error response
        return DnsMessage(
            header = originalQuery.header.copy(
                queryResponse = true,
                authoritativeAnswer = false,
                truncatedMessage = false,
                recursionAvailable = false,
                reserved = 0,
                responseCode = 2, // Server failure
                questionCount = originalQuery.questions.size,
                answerCount = 0,
                authorityCount = 0,
                additionalCount = 0
            ),
            questions = originalQuery.questions
        )
    } finally {
        resolverSocket.close()
    }
}

fun createDnsReply(originalHeader: DnsMessage.DnsHeader,
                   originalQuestions: List<DnsMessage.DnsQuestion>): DnsMessage {
    // Set RCODE based on OPCODE: 0 if OPCODE is 0 (standard query), else 4 (not implemented)
    val responseCode = if (originalHeader.operationCode == 0) 0 else 4

    // Ensure at least 1 non-empty question
    val questions: List<DnsMessage.DnsQuestion> =
        if (originalQuestions.isEmpty() || originalQuestions.any { it.name.isEmpty() })
            listOf(createCodeCraftersQuestion())
        else
            originalQuestions

    // Create answer records for each question
    val answers = questions.map { question ->
        createAnswerRecord(question.name)
    }

    return DnsMessage(
        header = originalHeader.copy(
            // Mimic the packet identifier from the request
            id = originalHeader.id,
            queryResponse = true,           // Set QR bit to 1 (response)
            // Mimic the OPCODE value from the request
            operationCode = originalHeader.operationCode,
            authoritativeAnswer = false,    // Set AA to 0
            truncatedMessage = false,       // Set TC to 0
            // Mimic the RD value from the request
            recursionDesired = originalHeader.recursionDesired,
            recursionAvailable = false,     // Set RA to 0
            reserved = 0,                   // Set Z to 0
            responseCode = responseCode,    // Set RCODE based on OPCODE
            questionCount = originalQuestions.size,  // Match number of questions
            answerCount = originalQuestions.size,    // One answer per question
            authorityCount = 0,             // No authority records
            additionalCount = 0             // No additional records
        ),
        questions = questions,      // Echo back all questions (uncompressed)
        answers = answers                   // Provide answers for all questions
    )
}

// Helper function to create a standard codecrafters.io question for testing
fun createCodeCraftersQuestion(): DnsMessage.DnsQuestion {
    return DnsMessage.DnsQuestion(
        name = "codecrafters.io",
        type = DnsMessage.DnsType(1),      // A record
        classCode = DnsMessage.DnsClass(1) // IN class
    )
}

fun createAnswerRecord(domainName: String): DnsMessage.DnsRecord {
    val ipAddress = byteArrayOf(8, 8, 8, 8)          // 8.8.8.8 as example

    return DnsMessage.DnsRecord(
        name = domainName,                           // Mimic the domain name from the question
        type = DnsMessage.DnsType(1),        // A record
        classCode = DnsMessage.DnsClass(1),  // IN class
        ttl = 60,                                   // 60 seconds TTL
        len = 4,                                    // Length of IP address data
        data = ipAddress
    )
}
