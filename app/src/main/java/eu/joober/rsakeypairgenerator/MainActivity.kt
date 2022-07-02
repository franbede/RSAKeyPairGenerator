package eu.joober.rsakeypairgenerator

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.TextView
import eu.joober.rsakeypairgenerator.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Example of a call to a native method
        binding.sampleText.text = generateRSAKeyPair()?.get(0)?: ""
    }

    /**
     * A native method that is implemented by the 'rsakeypairgenerator' native library,
     * which is packaged with this application.
     */
    private external fun generateRSAKeyPair(): Array<String>?

    companion object {
        // Used to load the 'rsakeypairgenerator' library on application startup.
        init {
            System.loadLibrary("rsakeypairgenerator")
        }
    }
}