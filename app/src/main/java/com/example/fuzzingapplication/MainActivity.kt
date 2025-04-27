package com.example.fuzzingapplication

import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    
    companion object {
        private const val TAG = "FuzzingTest"
    }

    private lateinit var textViewInput: EditText
    private lateinit var buttonProcess: Button
    private lateinit var textViewOutput: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        textViewInput = findViewById(R.id.textViewInput)
        buttonProcess = findViewById(R.id.buttonProcess)
        textViewOutput = findViewById(R.id.TextInput)  // Using existing TextView

        buttonProcess.setOnClickListener {
            processAndLogText(textViewInput.text.toString())
        }
    }

    public fun processAndLogText(input: String) {
        // This is the function we'll use for fuzzing testing
        try {
            // Add some basic text processing here
            val processed = input.trim().uppercase()
            
            // Log the input and processed text
            Log.d(TAG, "Original input: $input")
            Log.d(TAG, "Processed text: $processed")
            
            // Process and display text
            if (processed.isEmpty()) {
                Log.w(TAG, "Empty input received")
                textViewOutput.text = "Empty input received"
            } else {
                // Example of some string manipulation that could be fuzzed
                val reversed = processed.reversed()
                val length = processed.length
                
                // Create a formatted output string
                val outputText = """
                    Original: $processed
                    Reversed: $reversed
                    Length: $length
                """.trimIndent()
                
                // Update the TextView on the UI thread
                runOnUiThread {
                    textViewOutput.text = outputText
                }
                
                Log.d(TAG, "Reversed: $reversed, Length: $length")
            }
        } catch (e: Exception) {
            // Log any exceptions that occur during processing
            Log.e(TAG, "Error processing text: ${e.message}", e)
            // Show error in TextView
            runOnUiThread {
                textViewOutput.text = "Error: ${e.message}"
            }
        }
    }
}