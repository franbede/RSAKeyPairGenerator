package eu.joober.rsakeypairgenerator

object EncryptionUtils {
    init {
        System.loadLibrary("rsakeypairgenerator")
    }

    external fun generateRSAKeyPair(): Array<String>?
}