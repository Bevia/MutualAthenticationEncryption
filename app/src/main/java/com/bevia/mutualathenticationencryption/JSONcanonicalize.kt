package com.bevia.mutualathenticationencryption

import org.json.JSONObject
import java.util.TreeMap

/*
how would I canonicalize this in kotlin?

 var epoch = Date.now() / 1000;
              var request = {
                  "epoch": epoch.toString(),
                  "method": "post",
                  "query": "",
                  "path": "/v1/users",
                  "body": {
                      "device_id": demo["device_id"],
                      "public_key": public
                  }
              };

 */
class JSONcanonicalize {

    fun setCanonicalize(jsonObject: JSONObject): String {

        val epoch = System.currentTimeMillis() / 1000

        // Create the JSON object with the original structure
        val request = JSONObject(
            mapOf(
                "epoch" to epoch.toString(),
                "method" to "post",
                "query" to "",
                "path" to "/v1/users",
                "body" to mapOf(
                    "device_id" to "demo_device_id",  // Replace with actual device ID
                    "public_key" to "your_public_key"  // Replace with actual public key
                )
            )
        )

        // Canonicalize the JSON object
        val canonicalJson = canonicalizeJson(request)

        // Print the canonicalized JSON string
        println(canonicalJson)

        return canonicalJson
    }

    fun canonicalizeJson(jsonObject: JSONObject): String {
        // Sort the keys of the JSON object using TreeMap (which sorts keys by natural order)
        val sortedMap = TreeMap<String, Any?>()

        // Iterate through the keys and values of the JSONObject
        for (key in jsonObject.keys()) {
            val value = jsonObject.get(key)
            // If the value is a nested JSONObject, recursively sort it as well
            sortedMap[key] = if (value is JSONObject) {
                canonicalizeJson(value) // Recursively sort nested objects
            } else {
                value
            }
        }

        // Recreate a sorted JSON object from the sorted map
        return JSONObject(sortedMap as Map<String, Any?>).toString()
    }

}