
          #ifndef AviaryJob_CONTROLJOB_H
          #define AviaryJob_CONTROLJOB_H
        
      
       /**
        * ControlJob.h
        *
        * This file was auto-generated from WSDL
        * by the Apache Axis2/Java version: 1.0  Built on : Jul 17, 2012 (04:42:24 EDT)
        */

       /**
        *  ControlJob class
        */

        namespace AviaryJob{
            class ControlJob;
        }
        

        
                #include "AviaryCommon_JobID.h"
              

        #include <stdio.h>
        #include <OMElement.h>
        #include <ServiceClient.h>
        #include <ADBDefines.h>

namespace AviaryJob
{
        
        

        class ControlJob {

        private:
             AviaryCommon::JobID* property_Id;

                
                bool isValidId;
            std::string property_Reason;

                
                bool isValidReason;
            

        /*** Private methods ***/
          

        bool WSF_CALL
        setIdNil();
            

        bool WSF_CALL
        setReasonNil();
            



        /******************************* public functions *********************************/

        public:

        /**
         * Constructor for class ControlJob
         */

        ControlJob();

        /**
         * Destructor ControlJob
         */
        ~ControlJob();


       

        /**
         * Constructor for creating ControlJob
         * @param 
         * @param Id AviaryCommon::JobID*
         * @param Reason std::string
         * @return newly created ControlJob object
         */
        ControlJob(AviaryCommon::JobID* arg_Id,std::string arg_Reason);
        

        /**
         * resetAll for ControlJob
         */
        WSF_EXTERN bool WSF_CALL resetAll();
        
        /********************************** Class get set methods **************************************/
        
        

        /**
         * Getter for id. 
         * @return AviaryCommon::JobID*
         */
        WSF_EXTERN AviaryCommon::JobID* WSF_CALL
        getId();

        /**
         * Setter for id.
         * @param arg_Id AviaryCommon::JobID*
         * @return true on success, false otherwise
         */
        WSF_EXTERN bool WSF_CALL
        setId(AviaryCommon::JobID*  arg_Id);

        /**
         * Re setter for id
         * @return true on success, false
         */
        WSF_EXTERN bool WSF_CALL
        resetId();
        
        

        /**
         * Getter for reason. 
         * @return std::string*
         */
        WSF_EXTERN std::string WSF_CALL
        getReason();

        /**
         * Setter for reason.
         * @param arg_Reason std::string*
         * @return true on success, false otherwise
         */
        WSF_EXTERN bool WSF_CALL
        setReason(const std::string  arg_Reason);

        /**
         * Re setter for reason
         * @return true on success, false
         */
        WSF_EXTERN bool WSF_CALL
        resetReason();
        


        /******************************* Checking and Setting NIL values *********************************/
        

        /**
         * NOTE: set_nil is only available for nillable properties
         */

        

        /**
         * Check whether id is Nill
         * @return true if the element is Nil, false otherwise
         */
        bool WSF_CALL
        isIdNil();


        

        /**
         * Check whether reason is Nill
         * @return true if the element is Nil, false otherwise
         */
        bool WSF_CALL
        isReasonNil();


        

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
         * @param ControlJob_om_node node to serialize from
         * @param ControlJob_om_element parent element to serialize from
         * @param tag_closed Whether the parent tag is closed or not
         * @param namespaces hash of namespace uris to prefixes
         * @param next_ns_index an int which contains the next namespace index
         * @return axiom_node_t on success,NULL otherwise.
         */
        axiom_node_t* WSF_CALL
        serialize(axiom_node_t* ControlJob_om_node, axiom_element_t *ControlJob_om_element, int tag_closed, axutil_hash_t *namespaces, int *next_ns_index);

        /**
         * Check whether the ControlJob is a particle class (E.g. group, inner sequence)
         * @return true if this is a particle class, false otherwise.
         */
        bool WSF_CALL
        isParticle();



        /******************************* get the value by the property number  *********************************/
        /************NOTE: This method is introduced to resolve a problem in unwrapping mode *******************/

      
        

        /**
         * Getter for id by property number (1)
         * @return AviaryCommon::JobID
         */

        AviaryCommon::JobID* WSF_CALL
        getProperty1();

    
        

        /**
         * Getter for reason by property number (2)
         * @return std::string
         */

        std::string WSF_CALL
        getProperty2();

    

};

}        
 #endif /* CONTROLJOB_H */
    

