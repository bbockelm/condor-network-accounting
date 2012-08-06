

        /**
         * SuspendJob.cpp
         *
         * This file was auto-generated from WSDL
         * by the Apache Axis2/C version: SNAPSHOT  Built on : Mar 10, 2008 (08:35:52 GMT+00:00)
         */
        
            #include "AviaryJob_SuspendJob.h"
          

       #ifdef __GNUC__
       #pragma GCC diagnostic ignored "-Wunused-variable"
       #pragma GCC diagnostic ignored "-Wunused-value"
       #pragma GCC diagnostic ignored "-Wunused-but-set-variable"
       #pragma GCC diagnostic ignored "-Wunused-parameter"
       #pragma GCC diagnostic ignored "-Wcast-qual"
       #pragma GCC diagnostic ignored "-Wshadow"
       #pragma GCC diagnostic ignored "-Wwrite-strings"
       #endif
        
        #include <Environment.h>
        #include <WSFError.h>


        using namespace wso2wsf;
        using namespace std;
        
        using namespace AviaryJob;
        
               /*
                * Implementation of the SuspendJob|http://job.aviary.grid.redhat.com Element
                */
           AviaryJob::SuspendJob::SuspendJob()
        {

        
            qname = NULL;
        
                property_SuspendJob  = NULL;
              
            isValidSuspendJob  = false;
        
                  qname =  axutil_qname_create (Environment::getEnv(),
                        "SuspendJob",
                        "http://job.aviary.grid.redhat.com",
                        NULL);
                
        }

       AviaryJob::SuspendJob::SuspendJob(AviaryJob::ControlJob* arg_SuspendJob)
        {
             
                   qname = NULL;
             
               property_SuspendJob  = NULL;
             
            isValidSuspendJob  = true;
            
                 qname =  axutil_qname_create (Environment::getEnv(),
                       "SuspendJob",
                       "http://job.aviary.grid.redhat.com",
                       NULL);
               
                    property_SuspendJob = arg_SuspendJob;
            
        }
        AviaryJob::SuspendJob::~SuspendJob()
        {
            resetAll();
        }

        bool WSF_CALL AviaryJob::SuspendJob::resetAll()
        {
            //calls reset method for all the properties owned by this method which are pointers.

            
             resetSuspendJob();//AviaryJob::ControlJob
          if(qname != NULL)
          {
            axutil_qname_free( qname, Environment::getEnv());
            qname = NULL;
          }
        
            return true;

        }

        

        bool WSF_CALL
        AviaryJob::SuspendJob::deserialize(axiom_node_t** dp_parent,bool *dp_is_early_node_valid, bool dont_care_minoccurs)
        {
          axiom_node_t *parent = *dp_parent;
          
          bool status = AXIS2_SUCCESS;
           
         const axis2_char_t* text_value = NULL;
         axutil_qname_t *mqname = NULL;
          
            axutil_qname_t *element_qname = NULL; 
            
               axiom_node_t *first_node = NULL;
               bool is_early_node_valid = true;
               axiom_node_t *current_node = NULL;
               axiom_element_t *current_element = NULL;
            
              
              while(parent && axiom_node_get_node_type(parent, Environment::getEnv()) != AXIOM_ELEMENT)
              {
                  parent = axiom_node_get_next_sibling(parent, Environment::getEnv());
              }
              if (NULL == parent)
              {   
                return AXIS2_FAILURE;
              }
              

                    current_element = (axiom_element_t *)axiom_node_get_data_element(parent, Environment::getEnv());
                    mqname = axiom_element_get_qname(current_element, Environment::getEnv(), parent);
                    if (axutil_qname_equals(mqname, Environment::getEnv(), this->qname))
                    {
                        
                          first_node = parent;
                          
                    }
                    else
                    {
                        WSF_LOG_ERROR_MSG(Environment::getEnv()->log, WSF_LOG_SI,
                              "Failed in building adb object for SuspendJob : "
                              "Expected %s but returned %s",
                              axutil_qname_to_string(qname, Environment::getEnv()),
                              axutil_qname_to_string(mqname, Environment::getEnv()));
                        
                        return AXIS2_FAILURE;
                    }
                    

                     
                     /*
                      * building SuspendJob element
                      */
                     
                     
                     
                                   current_node = first_node;
                                   is_early_node_valid = false;
                                   
                                   
                                    while(current_node && axiom_node_get_node_type(current_node, Environment::getEnv()) != AXIOM_ELEMENT)
                                    {
                                        current_node = axiom_node_get_next_sibling(current_node, Environment::getEnv());
                                    }
                                    if(current_node != NULL)
                                    {
                                        current_element = (axiom_element_t *)axiom_node_get_data_element(current_node, Environment::getEnv());
                                        mqname = axiom_element_get_qname(current_element, Environment::getEnv(), current_node);
                                    }
                                   
                                 element_qname = axutil_qname_create(Environment::getEnv(), "SuspendJob", "http://job.aviary.grid.redhat.com", NULL);
                                 

                           if (isParticle() ||  
                                (current_node   && current_element && (axutil_qname_equals(element_qname, Environment::getEnv(), mqname))))
                           {
                              if( current_node   && current_element && (axutil_qname_equals(element_qname, Environment::getEnv(), mqname)))
                              {
                                is_early_node_valid = true;
                              }
                              
                                 AviaryJob::ControlJob* element = new AviaryJob::ControlJob();

                                      status =  element->deserialize(&current_node, &is_early_node_valid, false);
                                      if(AXIS2_FAILURE == status)
                                      {
                                          WSF_LOG_ERROR_MSG(Environment::getEnv()->log, WSF_LOG_SI, "failed in building adb object for element SuspendJob");
                                      }
                                      else
                                      {
                                          status = setSuspendJob(element);
                                      }
                                    
                                 if(AXIS2_FAILURE ==  status)
                                 {
                                     WSF_LOG_ERROR_MSG( Environment::getEnv()->log,WSF_LOG_SI,"failed in setting the value for SuspendJob ");
                                     if(element_qname)
                                     {
                                         axutil_qname_free(element_qname, Environment::getEnv());
                                     }
                                     return AXIS2_FAILURE;
                                 }
                              }
                           
                              else if(!dont_care_minoccurs)
                              {
                                  if(element_qname)
                                  {
                                      axutil_qname_free(element_qname, Environment::getEnv());
                                  }
                                  /* this is not a nillable element*/
				  WSF_LOG_ERROR_MSG(Environment::getEnv()->log,WSF_LOG_SI, "non nillable or minOuccrs != 0 element SuspendJob missing");
                                  return AXIS2_FAILURE;
                              }
                           
                  if(element_qname)
                  {
                     axutil_qname_free(element_qname, Environment::getEnv());
                     element_qname = NULL;
                  }
                 
          return status;
       }

          bool WSF_CALL
          AviaryJob::SuspendJob::isParticle()
          {
            
                 return false;
              
          }


          void WSF_CALL
          AviaryJob::SuspendJob::declareParentNamespaces(
                    axiom_element_t *parent_element,
                    axutil_hash_t *namespaces, int *next_ns_index)
          {
            
                  /* Here this is an empty function, Nothing to declare */
                 
          }

        
        
        axiom_node_t* WSF_CALL
	AviaryJob::SuspendJob::serialize(axiom_node_t *parent, 
			axiom_element_t *parent_element, 
			int parent_tag_closed, 
			axutil_hash_t *namespaces, 
			int *next_ns_index)
        {
            
            
         
         axiom_node_t *current_node = NULL;
         int tag_closed = 0;

         
         
                axiom_namespace_t *ns1 = NULL;

                axis2_char_t *qname_uri = NULL;
                axis2_char_t *qname_prefix = NULL;
                axis2_char_t *p_prefix = NULL;
            
                    axis2_char_t text_value_1[ADB_DEFAULT_DIGIT_LIMIT];
                    
               axis2_char_t *start_input_str = NULL;
               axis2_char_t *end_input_str = NULL;
               unsigned int start_input_str_len = 0;
               unsigned int end_input_str_len = 0;
            
            
               axiom_data_source_t *data_source = NULL;
               axutil_stream_t *stream = NULL;

             
                int next_ns_index_value = 0;
             
                    namespaces = axutil_hash_make(Environment::getEnv());
                    next_ns_index = &next_ns_index_value;
                     
                           ns1 = axiom_namespace_create (Environment::getEnv(),
                                             "http://job.aviary.grid.redhat.com",
                                             "n"); 
                           axutil_hash_set(namespaces, "http://job.aviary.grid.redhat.com", AXIS2_HASH_KEY_STRING, axutil_strdup(Environment::getEnv(), "n"));
                       
                     
                    parent_element = axiom_element_create (Environment::getEnv(), NULL, "SuspendJob", ns1 , &parent);
                    
                    
                    axiom_element_set_namespace(parent_element, Environment::getEnv(), ns1, parent);


            
                    data_source = axiom_data_source_create(Environment::getEnv(), parent, &current_node);
                    stream = axiom_data_source_get_stream(data_source, Environment::getEnv());
                  
                       if(!(p_prefix = (axis2_char_t*)axutil_hash_get(namespaces, "http://job.aviary.grid.redhat.com", AXIS2_HASH_KEY_STRING)))
                       {
                           p_prefix = (axis2_char_t*)AXIS2_MALLOC(Environment::getEnv()->allocator, sizeof (axis2_char_t) * ADB_DEFAULT_NAMESPACE_PREFIX_LIMIT);
                           sprintf(p_prefix, "n%d", (*next_ns_index)++);
                           axutil_hash_set(namespaces, "http://job.aviary.grid.redhat.com", AXIS2_HASH_KEY_STRING, p_prefix);
                           
                           axiom_element_declare_namespace_assume_param_ownership(parent_element, Environment::getEnv(), axiom_namespace_create (Environment::getEnv(),
                                            "http://job.aviary.grid.redhat.com", p_prefix));
                       }
                      

                   if (!isValidSuspendJob)
                   {
                      
                            
                            WSF_LOG_ERROR_MSG( Environment::getEnv()->log,WSF_LOG_SI,"Nil value found in non-nillable property SuspendJob");
                            return NULL;
                          
                   }
                   else
                   {
                     start_input_str = (axis2_char_t*)AXIS2_MALLOC(Environment::getEnv()->allocator, sizeof(axis2_char_t) *
                                 (4 + axutil_strlen(p_prefix) + 
                                  axutil_strlen("SuspendJob"))); 
                                 
                                 /* axutil_strlen("<:>") + 1 = 4 */
                     end_input_str = (axis2_char_t*)AXIS2_MALLOC(Environment::getEnv()->allocator, sizeof(axis2_char_t) *
                                 (5 + axutil_strlen(p_prefix) + axutil_strlen("SuspendJob")));
                                  /* axutil_strlen("</:>") + 1 = 5 */
                                  
                     

                   
                   
                     
                     /*
                      * parsing SuspendJob element
                      */

                    
                    
                            sprintf(start_input_str, "<%s%sSuspendJob",
                                 p_prefix?p_prefix:"",
                                 (p_prefix && axutil_strcmp(p_prefix, ""))?":":""); 
                            
                        start_input_str_len = axutil_strlen(start_input_str);
                        sprintf(end_input_str, "</%s%sSuspendJob>",
                                 p_prefix?p_prefix:"",
                                 (p_prefix && axutil_strcmp(p_prefix, ""))?":":"");
                        end_input_str_len = axutil_strlen(end_input_str);
                    property_SuspendJob->serialize(current_node, parent_element,
                                                                                 property_SuspendJob->isParticle() || true, namespaces, next_ns_index);
                            
                     
                     AXIS2_FREE(Environment::getEnv()->allocator,start_input_str);
                     AXIS2_FREE(Environment::getEnv()->allocator,end_input_str);
                 } 

                 
                   if(namespaces)
                   {
                       axutil_hash_index_t *hi;
                       void *val;
                       for (hi = axutil_hash_first(namespaces, Environment::getEnv()); hi; hi = axutil_hash_next(Environment::getEnv(), hi))
                       {
                           axutil_hash_this(hi, NULL, NULL, &val);
                           AXIS2_FREE(Environment::getEnv()->allocator, val);
                       }
                       axutil_hash_free(namespaces, Environment::getEnv());
                   }
                

            return parent;
        }


        

            /**
             * Getter for SuspendJob by  Property Number 1
             */
            AviaryJob::ControlJob* WSF_CALL
            AviaryJob::SuspendJob::getProperty1()
            {
                return getSuspendJob();
            }

            /**
             * getter for SuspendJob.
             */
            AviaryJob::ControlJob* WSF_CALL
            AviaryJob::SuspendJob::getSuspendJob()
             {
                return property_SuspendJob;
             }

            /**
             * setter for SuspendJob
             */
            bool WSF_CALL
            AviaryJob::SuspendJob::setSuspendJob(
                    AviaryJob::ControlJob*  arg_SuspendJob)
             {
                

                if(isValidSuspendJob &&
                        arg_SuspendJob == property_SuspendJob)
                {
                    
                    return true;
                }

                
                  if(NULL == arg_SuspendJob)
                       
                  {
                      WSF_LOG_ERROR_MSG( Environment::getEnv()->log,WSF_LOG_SI,"SuspendJob is being set to NULL, but it is not a nullable element");
                      return AXIS2_FAILURE;
                  }
                

                
                resetSuspendJob();

                
                    if(NULL == arg_SuspendJob)
                         
                {
                    /* We are already done */
                    return true;
                }
                
                        property_SuspendJob = arg_SuspendJob;
                        isValidSuspendJob = true;
                    
                return true;
             }

             

           /**
            * resetter for SuspendJob
            */
           bool WSF_CALL
           AviaryJob::SuspendJob::resetSuspendJob()
           {
               int i = 0;
               int count = 0;


               
            
                

                if(property_SuspendJob != NULL)
                {
                   
                   
                         delete  property_SuspendJob;
                     

                   }

                
                
                
               isValidSuspendJob = false; 
               return true;
           }

           /**
            * Check whether SuspendJob is nill
            */
           bool WSF_CALL
           AviaryJob::SuspendJob::isSuspendJobNil()
           {
               return !isValidSuspendJob;
           }

           /**
            * Set SuspendJob to nill (currently the same as reset)
            */
           bool WSF_CALL
           AviaryJob::SuspendJob::setSuspendJobNil()
           {
               return resetSuspendJob();
           }

           

