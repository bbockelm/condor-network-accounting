

        #ifndef AviaryLocator_LOCATE_H
        #define AviaryLocator_LOCATE_H

       /**
        * Locate.h
        *
        * This file was auto-generated from WSDL
        * by the Apache Axis2/Java version: 1.0  Built on : Sep 07, 2011 (03:40:57 EDT)
        */

       /**
        *  Locate class
        */

        namespace AviaryLocator{
            class Locate;
        }
        

        
       #include "AviaryCommon_ResourceID.h"
          
        #include <axutil_qname.h>
        

        #include <stdio.h>
        #include <OMElement.h>
        #include <ServiceClient.h>
        #include <ADBDefines.h>

namespace AviaryLocator
{
        
        

        class Locate {

        private:
             
                axutil_qname_t* qname;
            std::vector<AviaryCommon::ResourceID*>* property_Ids;

                
                bool isValidIds;
            bool property_PartialMatches;

                
                bool isValidPartialMatches;
            

        /*** Private methods ***/
          

        bool WSF_CALL
        setIdsNil();
            



        /******************************* public functions *********************************/

        public:

        /**
         * Constructor for class Locate
         */

        Locate();

        /**
         * Destructor Locate
         */
        ~Locate();


       

        /**
         * Constructor for creating Locate
         * @param 
         * @param Ids std::vector<AviaryCommon::ResourceID*>*
         * @param PartialMatches bool
         * @return newly created Locate object
         */
        Locate(std::vector<AviaryCommon::ResourceID*>* arg_Ids,bool arg_PartialMatches);
        
        
        /********************************** Class get set methods **************************************/
        /******** Deprecated for array types, Use 'Getters and Setters for Arrays' instead ***********/
        

        /**
         * Getter for ids. Deprecated for array types, Use getIdsAt instead
         * @return Array of AviaryCommon::ResourceID*s.
         */
        WSF_EXTERN std::vector<AviaryCommon::ResourceID*>* WSF_CALL
        getIds();

        /**
         * Setter for ids.Deprecated for array types, Use setIdsAt
         * or addIds instead.
         * @param arg_Ids Array of AviaryCommon::ResourceID*s.
         * @return true on success, false otherwise
         */
        WSF_EXTERN bool WSF_CALL
        setIds(std::vector<AviaryCommon::ResourceID*>*  arg_Ids);

        /**
         * Re setter for ids
         * @return true on success, false
         */
        WSF_EXTERN bool WSF_CALL
        resetIds();
        
        

        /**
         * Getter for partialMatches. 
         * @return bool
         */
        WSF_EXTERN bool WSF_CALL
        getPartialMatches();

        /**
         * Setter for partialMatches.
         * @param arg_PartialMatches bool
         * @return true on success, false otherwise
         */
        WSF_EXTERN bool WSF_CALL
        setPartialMatches(bool  arg_PartialMatches);

        /**
         * Re setter for partialMatches
         * @return true on success, false
         */
        WSF_EXTERN bool WSF_CALL
        resetPartialMatches();
        
        /****************************** Get Set methods for Arrays **********************************/
        /************ Array Specific Operations: get_at, set_at, add, remove_at, sizeof *****************/

        /**
         * E.g. use of get_at, set_at, add and sizeof
         *
         * for(i = 0; i < adb_element->sizeofProperty(); i ++ )
         * {
         *     // Getting ith value to property_object variable
         *     property_object = adb_element->getPropertyAt(i);
         *
         *     // Setting ith value from property_object variable
         *     adb_element->setPropertyAt(i, property_object);
         *
         *     // Appending the value to the end of the array from property_object variable
         *     adb_element->addProperty(property_object);
         *
         *     // Removing the ith value from an array
         *     adb_element->removePropertyAt(i);
         *     
         * }
         *
         */

        
        
        /**
         * Get the ith element of ids.
        * @param i index of the item to be obtained
         * @return ith AviaryCommon::ResourceID* of the array
         */
        WSF_EXTERN AviaryCommon::ResourceID* WSF_CALL
        getIdsAt(int i);

        /**
         * Set the ith element of ids. (If the ith already exist, it will be replaced)
         * @param i index of the item to return
         * @param arg_Ids element to set AviaryCommon::ResourceID* to the array
         * @return ith AviaryCommon::ResourceID* of the array
         */
        WSF_EXTERN bool WSF_CALL
        setIdsAt(int i,
                AviaryCommon::ResourceID* arg_Ids);


        /**
         * Add to ids.
         * @param arg_Ids element to add AviaryCommon::ResourceID* to the array
         * @return true on success, false otherwise.
         */
        WSF_EXTERN bool WSF_CALL
        addIds(
            AviaryCommon::ResourceID* arg_Ids);

        /**
         * Get the size of the ids array.
         * @return the size of the ids array.
         */
        WSF_EXTERN int WSF_CALL
        sizeofIds();

        /**
         * Remove the ith element of ids.
         * @param i index of the item to remove
         * @return true on success, false otherwise.
         */
        WSF_EXTERN bool WSF_CALL
        removeIdsAt(int i);

        


        /******************************* Checking and Setting NIL values *********************************/
        /* Use 'Checking and Setting NIL values for Arrays' to check and set nil for individual elements */

        /**
         * NOTE: set_nil is only available for nillable properties
         */

        

        /**
         * Check whether ids is Nill
         * @return true if the element is Nil, false otherwise
         */
        bool WSF_CALL
        isIdsNil();


        

        /**
         * Check whether partialMatches is Nill
         * @return true if the element is Nil, false otherwise
         */
        bool WSF_CALL
        isPartialMatchesNil();


        
        /**
         * Set partialMatches to Nill (same as using reset)
         * @return true on success, false otherwise.
         */
        bool WSF_CALL
        setPartialMatchesNil();
        

        /*************************** Checking and Setting 'NIL' values in Arrays *****************************/

        /**
         * NOTE: You may set this to remove specific elements in the array
         *       But you can not remove elements, if the specific property is declared to be non-nillable or sizeof(array) < minOccurs
         */
        
        /**
         * Check whether ids is Nill at position i
         * @param i index of the item to return.
         * @return true if the value is Nil at position i, false otherwise
         */
        bool WSF_CALL
        isIdsNilAt(int i);
 
       
        /**
         * Set ids to NILL at the  position i.
         * @param i . The index of the item to be set Nill.
         * @return true on success, false otherwise.
         */
        bool WSF_CALL
        setIdsNilAt(int i);

        

        /**************************** Serialize and De serialize functions ***************************/
        /*********** These functions are for use only inside the generated code *********************/

        
        /**
         * Deserialize the ADB object to an XML
         * @param dp_parent double pointer to the parent node to be deserialized
         * @param dp_is_early_node_valid double pointer to a flag (is_early_node_valid?)
         * @param dont_care_minoccurs Dont set errors on validating minoccurs, 
         *              (Parent will order this in a case of choice)
         * @return true on success, false otherwise
         */
        bool WSF_CALL
        deserialize(axiom_node_t** omNode, bool *isEarlyNodeValid, bool dontCareMinoccurs);
                         
            

       /**
         * Declare namespace in the most parent node 
         * @param parent_element parent element
         * @param namespaces hash of namespace uri to prefix
         * @param next_ns_index pointer to an int which contain the next namespace index
         */
        void WSF_CALL
        declareParentNamespaces(axiom_element_t *parent_element, axutil_hash_t *namespaces, int *next_ns_index);


        

        /**
         * Serialize the ADB object to an xml
         * @param Locate_om_node node to serialize from
         * @param Locate_om_element parent element to serialize from
         * @param tag_closed Whether the parent tag is closed or not
         * @param namespaces hash of namespace uris to prefixes
         * @param next_ns_index an int which contains the next namespace index
         * @return axiom_node_t on success,NULL otherwise.
         */
        axiom_node_t* WSF_CALL
        serialize(axiom_node_t* Locate_om_node, axiom_element_t *Locate_om_element, int tag_closed, axutil_hash_t *namespaces, int *next_ns_index);

        /**
         * Check whether the Locate is a particle class (E.g. group, inner sequence)
         * @return true if this is a particle class, false otherwise.
         */
        bool WSF_CALL
        isParticle();



        /******************************* get the value by the property number  *********************************/
        /************NOTE: This method is introduced to resolve a problem in unwrapping mode *******************/

      
        

        /**
         * Getter for ids by property number (1)
         * @return Array of AviaryCommon::ResourceIDs.
         */

        std::vector<AviaryCommon::ResourceID*>* WSF_CALL
        getProperty1();

    
        

        /**
         * Getter for partialMatches by property number (2)
         * @return bool
         */

        bool WSF_CALL
        getProperty2();

    

};

}        
 #endif /* LOCATE_H */
    

