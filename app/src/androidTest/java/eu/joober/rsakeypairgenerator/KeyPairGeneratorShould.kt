package eu.joober.rsakeypairgenerator

import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Test
import org.junit.runner.RunWith


@RunWith(AndroidJUnit4::class)
class KeyPairGenerationShould {

    @Test
    fun beGeneratedCorrectly() {
        val keyPair = EncryptionUtils.generateRSAKeyPair()
        assert((keyPair?.get(0)?:"").isNotEmpty())
        assert((keyPair?.get(1)?:"").isNotEmpty())
    }
}