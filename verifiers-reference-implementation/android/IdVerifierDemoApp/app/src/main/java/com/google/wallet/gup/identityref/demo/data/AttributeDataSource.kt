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
package com.google.wallet.gup.identityref.demo.data

import com.google.wallet.gup.identityref.demo.Attribute

/**
 * A singleton object to hold the attribute definitions for different ID types.
 * This centralizes the data, making it easier to manage and reuse.
 */
object AttributeDataSource {

    val mdlAttributes = mapOf(
        "Family name" to Attribute(id = "family_name", name = "Family name", namespace = "org.iso.18013.5.1"),
        "Given names" to Attribute(id = "given_name", name = "Given names", namespace = "org.iso.18013.5.1"),
        "Date of birth" to Attribute(id = "birth_date", name = "Date of birth", namespace = "org.iso.18013.5.1"),
        "Date of issue" to Attribute(id = "issue_date", name = "Date of issue", namespace = "org.iso.18013.5.1"),
        "Date of expiry" to Attribute(id = "expiry_date", name = "Date of expiry", namespace = "org.iso.18013.5.1"),
        "Issuing country" to Attribute(id = "issuing_country", name = "Issuing country", namespace = "org.iso.18013.5.1"),
        "Issuing authority" to Attribute(id = "issuing_authority", name = "Issuing authority", namespace = "org.iso.18013.5.1"),
        "Licence number" to Attribute(id = "document_number", name = "Licence number", namespace = "org.iso.18013.5.1"),
        "Portrait" to Attribute(id = "portrait", name = "Portrait", namespace = "org.iso.18013.5.1"),
        "Administrative number" to Attribute(id = "administrative_number", name = "Administrative number", namespace = "org.iso.18013.5.1"),
        "Sex" to Attribute(id = "sex", name = "Sex", namespace = "org.iso.18013.5.1"),
        "Height (cm)" to Attribute(id = "height", name = "Height (cm)", namespace = "org.iso.18013.5.1"),
        "Weight (kg)" to Attribute(id = "weight", name = "Weight (kg)", namespace = "org.iso.18013.5.1"),
        "Eye colour" to Attribute(id = "eye_colour", name = "Eye colour", namespace = "org.iso.18013.5.1"),
        "Hair colour" to Attribute(id = "hair_colour", name = "Hair colour", namespace = "org.iso.18013.5.1"),
        "Place of birth" to Attribute(id = "birth_place", name = "Place of birth", namespace = "org.iso.18013.5.1"),
        "Permanent place of residence" to Attribute(id = "resident_address", name = "Permanent place of residence", namespace = "org.iso.18013.5.1"),
        "Portrait image timestamp" to Attribute(id = "portrait_capture_date", name = "Portrait image timestamp", namespace = "org.iso.18013.5.1"),
        "Age attestation: How old are you (in years)?" to Attribute(id = "age_in_years", name = "Age attestation: How old are you (in years)?", namespace = "org.iso.18013.5.1"),
        "Age attestation: In what year were you born?" to Attribute(id = "age_birth_year", name = "Age attestation: In what year were you born?", namespace = "org.iso.18013.5.1"),
        "Age attestation: Are you over NN?" to Attribute(id = "age_over_NN", name = "Age attestation: Are you over NN?", namespace = "org.iso.18013.5.1"),
        "Issuing jurisdiction" to Attribute(id = "issuing_jurisdiction", name = "Issuing jurisdiction", namespace = "org.iso.18013.5.1"),
        "Nationality" to Attribute(id = "nationality", name = "Nationality", namespace = "org.iso.18013.5.1"),
        "Resident city" to Attribute(id = "resident_city", name = "Resident city", namespace = "org.iso.18013.5.1"),
        "Resident state" to Attribute(id = "resident_state", name = "Resident state", namespace = "org.iso.18013.5.1"),
        "Resident postal code" to Attribute(id = "resident_postal_code", name = "Resident postal code", namespace = "org.iso.18013.5.1"),
        "Resident country" to Attribute(id = "resident_country", name = "Resident country", namespace = "org.iso.18013.5.1"),
        "Biometric template XX" to Attribute(id = "biometric_template_xx", name = "Biometric template XX", namespace = "org.iso.18013.5.1"),
        "Family name in national characters" to Attribute(id = "family_name_national_character", name = "Family name in national characters", namespace = "org.iso.18013.5.1"),
        "Given name in national characters" to Attribute(id = "given_name_national_character", name = "Given name in national characters", namespace = "org.iso.18013.5.1"),
        "Signature / usual mark" to Attribute(id = "signature_usual_mark", name = "Signature / usual mark", namespace = "org.iso.18013.5.1"),
        "Driving Privileges" to Attribute(id = "driving_privileges", name = "Driving Privileges", namespace = "org.iso.18013.5.1"),
        "UN Distinguishing Sign" to Attribute(id = "un_distinguishing_sign", name = "UN Distinguishing Sign", namespace = "org.iso.18013.5.1"),
        "Organ donor" to Attribute(id = "organ_donor", name = "Organ donor", namespace = "org.iso.18013.5.1.aamva"),
        "Compliance type" to Attribute(id = "DHS_compliance", name = "Compliance type", namespace = "org.iso.18013.5.1.aamva"),
        "Given name truncation" to Attribute(id = "given_name_truncation", name = "Given name truncation", namespace = "org.iso.18013.5.1.aamva"),
        "Family name truncation" to Attribute(id = "family_name_truncation", name = "Family name truncation", namespace = "org.iso.18013.5.1.aamva"),
        "Domestic categories of vehicles/restrictions/conditions" to Attribute(id = "domestic_driving_privileges", name = "Domestic categories of vehicles/restrictions/conditions", namespace = "org.iso.18013.5.1.aamva"),
        "EDL indicator" to Attribute(id = "EDL_credential", name = "EDL indicator", namespace = "org.iso.18013.5.1.aamva"),
        "Veteran" to Attribute(id = "veteran", name = "Veteran", namespace = "org.iso.18013.5.1.aamva"),
        "Age is Over 18" to Attribute(id = "age_over_18", name = "Age is Over 18", namespace = "org.iso.18013.5.1")
    )

    val idPassAttributes = mapOf(
        "Family Name" to Attribute(id = "family_name", name = "Family Name", namespace = "org.iso.18013.5.1"),
        "Given Name" to Attribute(id = "given_name", name = "Given Name", namespace = "org.iso.18013.5.1"),
        "Date of Birth" to Attribute(id = "birth_date", name = "Date of Birth", namespace = "org.iso.18013.5.1"),
        "Date of Issue" to Attribute(id = "issue_date", name = "Date of Issue", namespace = "org.iso.18013.5.1"),
        "Date of Expiry" to Attribute(id = "expiry_date", name = "Date of Expiry", namespace = "org.iso.18013.5.1"),
        "Issuing Country" to Attribute(id = "issuing_country", name = "Issuing Country", namespace = "org.iso.18013.5.1"),
        "Issuing Authority" to Attribute(id = "issuing_authority", name = "Issuing Authority", namespace = "org.iso.18013.5.1"),
        "Document Number" to Attribute(id = "document_number", name = "Document Number", namespace = "org.iso.18013.5.1"),
        "Portrait" to Attribute(id = "portrait", name = "Portrait", namespace = "org.iso.18013.5.1"),
        "Sex" to Attribute(id = "sex", name = "Sex", namespace = "org.iso.18013.5.1"),
        "Age over 18" to Attribute(id = "age_over_18", name = "Age over 18", namespace = "org.iso.18013.5.1"),
        "Age over 21" to Attribute(id = "age_over_21", name = "Age over 21", namespace = "org.iso.18013.5.1"),
        "Nationality" to Attribute(id = "nationality", name = "Nationality", namespace = "org.iso.18013.5.1"),
        "Issue Date of Underlying Document" to Attribute(id = "original_document_issue_date", name = "Issue Date of Underlying Document", namespace = "org.iso.18013.5.1")
    )

    val avAttributes = mapOf(
        // Namespace eu.europa.ec.av.1
        "Age over 18" to Attribute(id = "age_over_18", name = "Age over 18", namespace = "eu.europa.ec.av.1"),
        "Age over 21" to Attribute(id = "age_over_21", name = "Age over 21", namespace = "eu.europa.ec.av.1"),
        "Age in years" to Attribute(id = "age_in_years", name = "Age in years", namespace = "eu.europa.ec.av.1"),
        "Age birth year" to Attribute(id = "age_birth_year", name = "Age birth year", namespace = "eu.europa.ec.av.1")
    )

    val photoIdAttributes = mapOf(
        // Namespace org.iso.23220.1
        "Family Name" to Attribute(id = "family_name", name = "Family Name", namespace = "org.iso.23220.1"),
        "Given Name" to Attribute(id = "given_name", name = "Given Name", namespace = "org.iso.23220.1"),
        "Birth Date" to Attribute(id = "birth_date", name = "Birth Date", namespace = "org.iso.23220.1"),
        "Portrait Capture Date" to Attribute(id = "portrait_capture_date", name = "Portrait Capture Date", namespace = "org.iso.23220.1"),
        "Portrait" to Attribute(id = "portrait", name = "Portrait", namespace = "org.iso.23220.1"),
        "Issue Date" to Attribute(id = "issue_date", name = "Issue Date", namespace = "org.iso.23220.1"),
        "Expiry Date" to Attribute(id = "expiry_date", name = "Expiry Date", namespace = "org.iso.23220.1"),
        "Issuing Country" to Attribute(id = "issuing_country", name = "Issuing Country", namespace = "org.iso.23220.1"),
        "Issuing Authority" to Attribute(id = "issuing_authority", name = "Issuing Authority", namespace = "org.iso.23220.1"),
        "Resident Address" to Attribute(id = "resident_address", name = "Resident Address", namespace = "org.iso.23220.1"),
        "Resident City" to Attribute(id = "resident_city", name = "Resident City", namespace = "org.iso.23220.1"),
        "Resident Country" to Attribute(id = "resident_country", name = "Resident Country", namespace = "org.iso.23220.1"),
        "Sex" to Attribute(id = "sex", name = "Sex", namespace = "org.iso.23220.1"),
        "Nationality" to Attribute(id = "nationality", name = "Nationality", namespace = "org.iso.23220.1"),
        "Document Number" to Attribute(id = "document_number", name = "Document Number", namespace = "org.iso.23220.1"),
        "Issuing Subdivision" to Attribute(id = "issuing_subdivision", name = "Issuing Subdivision", namespace = "org.iso.23220.1"),

        // Namespace org.iso.23220.photoID.1
        "Person ID" to Attribute(id = "person_id", name = "Person ID", namespace = "org.iso.23220.photoID.1"),
        "Birth Country" to Attribute(id = "birth_country", name = "Birth Country", namespace = "org.iso.23220.photoID.1"),
        "Birth City" to Attribute(id = "birth_city", name = "Birth City", namespace = "org.iso.23220.photoID.1"),
        "Resident Street" to Attribute(id = "resident_street", name = "Resident Street", namespace = "org.iso.23220.photoID.1"),
        "Resident House Number" to Attribute(id = "resident_house_number", name = "Resident House Number", namespace = "org.iso.23220.photoID.1"),
        "Travel Document Type" to Attribute(id = "travel_document_type", name = "Travel Document Type", namespace = "org.iso.23220.photoID.1"),
        "Travel Document Number" to Attribute(id = "travel_document_number", name = "Travel Document Number", namespace = "org.iso.23220.photoID.1"),
        "Resident State" to Attribute(id = "resident_state", name = "Resident State", namespace = "org.iso.23220.photoID.1"),
        "Travel Document MRZ" to Attribute(id = "travel_document_mrz", name = "Travel Document MRZ", namespace = "org.iso.23220.photoID.1")
    )
}
