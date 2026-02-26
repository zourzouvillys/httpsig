package com.zourzouvillys.httpsig

/**
 * Base exception for HTTP signature operations.
 */
open class HttpSigException(message: String, cause: Throwable? = null) : Exception(message, cause)
