
          #ifndef AviaryCommon_ATTRIBUTETYPE_H
          #define AviaryCommon_ATTRIBUTETYPE_H
        
      
       /**
        * AttributeType.h
        *
        * This file was auto-generated from WSDL
        * by the Apache Axis2/Java version: 1.0  Built on : Jul 17, 2012 (04:42:24 EDT)
        */

       /**
        *  AttributeType class
        */

        namespace AviaryCommon{
            class AttributeType;
        }
        

        
        #include <axutil_qname.h>
        

        #include <stdio.h>
        #include <OMElement.h>
        #include <ServiceClient.h>
        #include <ADBDefines.h>

namespace AviaryCommon
{
        
        /* Enumeration for this type */
        typedef enum {
            AttributeType_INTEGER,
            AttributeType_FLOAT,
            AttributeType_STRING,
            AttributeType_EXPRESSION,
            AttributeType_BOOLEAN,
            AttributeType_UNDEFINED,
            AttributeType_ERROR
        } ADBAttributeTypeEnum;
        
        

        class AttributeType {

        private:
             
                axutil_qname_t* qname;
            std::string property_AttributeType;

                
                bool isValidAttributeType;
            

        /*** Private methods ***/
          

        bool WSF_CALL
        setAttributeTypeNil();
            



        /******************************* public functions *********************************/

        public:

        /**
         * Constructor for class AttributeType
         */

        AttributeType();

        /**
         * Destructor AttributeType
         */
        ~AttributeType();


       

        /**
         * Constructor for creating AttributeType
         * @param 
         * @param AttributeType std::string
         * @return newly created AttributeType object
         */
        AttributeType(std::string arg_AttributeType);
        AttributeType(const ADBAttributeTypeEnum arg_AttributeType);
        

        /**
         * resetAll for AttributeType
         */
        WSF_EXTERN bool WSF_CALL resetAll();
        
        /********************************** Class get set methods **************************************/
        
        

        /**
         * Getter for AttributeType. 
         * @return std::string*
         */
        WSF_EXTERN std::string WSF_CALL
        getAttributeType();

        /**
         * Setter for AttributeType.
         * @param arg_AttributeType std::string*
         * @return true on success, false otherwise
         */
        WSF_EXTERN bool WSF_CALL
        setAttributeType(const std::string  arg_AttributeType);

        /**
         * Re setter for AttributeType
         * @return true on success, false
         */
        WSF_EXTERN bool WSF_CALL
        resetAttributeType();
        
            
            /************************** Getters and Setters For Enumerations ********************************/
            /********************* Enumeration Specific Operations: get_enum, set_enum **********************/
            
            /**
            * Enum getter for AttributeType.
            * @return ADBAttributeTypeEnum; -1 on failure
            */
            ADBAttributeTypeEnum WSF_CALL
            getAttributeTypeEnum();
            
            /**
            * Enum setter for AttributeType.
            * @param arg_AttributeType ADBAttributeTypeEnum
            * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
            */
            bool WSF_CALL
            setAttributeTypeEnum(
            const ADBAttributeTypeEnum arg_AttributeType);
            
          


        /******************************* Checking and Setting NIL values *********************************/
        

        /**
         * NOTE: set_nil is only available for nillable properties
         */

        

        /**
         * Check whether AttributeType is Nill
         * @return true if the element is Nil, false otherwise
         */
        bool WSF_CALL
        isAttributeTypeNil();


        

        /**************************** Serialize and De serialize functions ***************************/
        /*********** These functions are for use only inside the generated code *********************/

        
        /**
         * Deserialize the content from a string to an ADB object
         * @param node_value to deserialize
         * @param parent_element The parent element if it is an element, NULL otherwise
         * @return true on success, false otherwise
         */
       bool WSF_CALL
       deserializeFromString(const axis2_char_t *node_value, axiom_node_t *parent);
        
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
         * Serialize ADB object to a string
         * @param namespaces hash which contains a mapping of namespace uris to prefixes
         * @return serialized string
         */
         char* WSF_CALL
         serializeToString(axutil_hash_t *namespaces);
        

        /**
         * Serialize the ADB object to an xml
         * @param AttributeType_om_node node to serialize from
         * @param AttributeType_om_element parent element to serialize from
         * @param tag_closed Whether the parent tag is closed or not
         * @param namespaces hash of namespace uris to prefixes
         * @param next_ns_index an int which contains the next namespace index
         * @return axiom_node_t on success,NULL otherwise.
         */
        axiom_node_t* WSF_CALL
        serialize(axiom_node_t* AttributeType_om_node, axiom_element_t *AttributeType_om_element, int tag_closed, axutil_hash_t *namespaces, int *next_ns_index);

        /**
         * Check whether the AttributeType is a particle class (E.g. group, inner sequence)
         * @return true if this is a particle class, false otherwise.
         */
        bool WSF_CALL
        isParticle();



        /******************************* get the value by the property number  *********************************/
        /************NOTE: This method is introduced to resolve a problem in unwrapping mode *******************/

      
        

        /**
         * Getter for AttributeType by property number (1)
         * @return std::string
         */

        std::string WSF_CALL
        getProperty1();

    

};

}        
 #endif /* ATTRIBUTETYPE_H */
    

