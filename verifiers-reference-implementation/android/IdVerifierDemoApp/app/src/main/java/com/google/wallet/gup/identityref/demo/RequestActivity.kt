/* Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
        You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */
package com.google.wallet.gup.identityref.demo

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import android.widget.RadioGroup
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.wallet.gup.identityref.demo.data.AttributeDataSource

class RequestActivity : AppCompatActivity() {

    private lateinit var mdlCheckbox: CheckBox
    private lateinit var idpassCheckbox: CheckBox
    private lateinit var avCheckbox: CheckBox
    private lateinit var photoIdCheckbox: CheckBox
    private lateinit var attributesContainer: LinearLayout
    private lateinit var zkCheckbox: CheckBox
    private lateinit var verifyButton: Button
    private lateinit var protocolRadioGroup: RadioGroup

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_request)

        mdlCheckbox = findViewById(R.id.mdl_checkbox)
        idpassCheckbox = findViewById(R.id.idpass_checkbox)
        avCheckbox = findViewById(R.id.av_checkbox)
        photoIdCheckbox = findViewById(R.id.photoid_checkbox)
        attributesContainer = findViewById(R.id.attributes_container)
        zkCheckbox = findViewById(R.id.zk_checkbox)
        verifyButton = findViewById(R.id.verify_button)
        protocolRadioGroup = findViewById(R.id.protocol_radio_group)

        mdlCheckbox.setOnCheckedChangeListener { _, _ -> updateAttributes() }
        idpassCheckbox.setOnCheckedChangeListener { _, _ -> updateAttributes() }
        avCheckbox.setOnCheckedChangeListener { _, _ -> updateAttributes() }
        photoIdCheckbox.setOnCheckedChangeListener { _, _ -> updateAttributes() }

        verifyButton.setOnClickListener {
            val selectedDoctypes = getSelectedDoctypes()
            val selectedAttributes = getSelectedAttributes()
            val requestZk = zkCheckbox.isChecked
            val selectedProtocol = getSelectedProtocol()

            val intent = Intent(this, ListActivity::class.java).apply {
                putStringArrayListExtra(Constants.EXTRA_SELECTED_DOCTYPES, ArrayList(selectedDoctypes))
                putParcelableArrayListExtra(Constants.EXTRA_SELECTED_ATTRIBUTES, ArrayList(selectedAttributes))
                putExtra(Constants.EXTRA_REQUEST_ZK, requestZk)
                putExtra(Constants.EXTRA_SELECTED_PROTOCOL, selectedProtocol)
            }
            startActivity(intent)
        }

        // Initial population of attributes
        updateAttributes()
    }
    private fun getSelectedProtocol(): String {
        return when (protocolRadioGroup.checkedRadioButtonId) {
            R.id.openid4vp_v1_unsigned_radio -> getString(R.string.protocol_openid4vp_v1_unsigned)
            R.id.openid4vp_v1_signed_radio -> getString(R.string.protocol_openid4vp_v1_signed)
            else -> getString(R.string.protocol_openid4vp)
        }
    }

    private fun updateAttributes() {
        attributesContainer.removeAllViews()
        val combinedAttributes = mutableMapOf<String, Attribute>()

        if (mdlCheckbox.isChecked) {
            AttributeDataSource.mdlAttributes.values.forEach { attribute ->
                attribute.id?.let { id ->
                    combinedAttributes[id] = attribute
                }
            }
        }
        if (idpassCheckbox.isChecked) {
            AttributeDataSource.idPassAttributes.values.forEach { attribute ->
                attribute.id?.let { id ->
                    if (!combinedAttributes.containsKey(id)) {
                        combinedAttributes[id] = attribute
                    }
                }
            }
        }
        if (avCheckbox.isChecked) {
            AttributeDataSource.avAttributes.values.forEach { attribute ->
                attribute.id?.let { id ->
                    if (!combinedAttributes.containsKey(id)) {
                        combinedAttributes[id] = attribute
                    }
                }
            }
        }
        if (photoIdCheckbox.isChecked) {
            AttributeDataSource.photoIdAttributes.values.forEach { attribute ->
                attribute.id?.let { id ->
                    if (!combinedAttributes.containsKey(id)) {
                        combinedAttributes[id] = attribute
                    }
                }
            }
        }

        val inflater = LayoutInflater.from(this)
        val sortedAttributes = combinedAttributes.values.sortedBy { it.name }

        for (attribute in sortedAttributes) {
            // Inflate the custom layout for each checkbox.
            // This ensures that the checkbox is styled correctly according to the theme.
            val checkBoxView = inflater.inflate(R.layout.list_item_attribute, attributesContainer, false) as MaterialCheckBox

            // Set the text and store the attribute object in the tag for later retrieval.
            checkBoxView.text = attribute.name
            checkBoxView.tag = attribute

            // Add the newly created and styled checkbox to the container.
            attributesContainer.addView(checkBoxView)
        }
    }

    private fun getSelectedDoctypes(): List<String> {
        val doctypes = mutableListOf<String>()
        if (mdlCheckbox.isChecked) {
            doctypes.add(getString(R.string.doctype_mdl))
        }
        if (idpassCheckbox.isChecked) {
            doctypes.add(getString(R.string.doctype_idpass))
        }
        if (avCheckbox.isChecked) {
            doctypes.add(getString(R.string.doctype_av))
        }
        if (photoIdCheckbox.isChecked) {
            doctypes.add(getString(R.string.doctype_photoid))
        }
        return doctypes
    }

    private fun getSelectedAttributes(): List<Attribute> {
        val selected = mutableListOf<Attribute>()
        for (i in 0 until attributesContainer.childCount) {
            val view = attributesContainer.getChildAt(i)
            if (view is CheckBox && view.isChecked) {
                // Retrieve the full Attribute object from the tag.
                selected.add(view.tag as Attribute)
            }
        }
        return selected
    }
}
