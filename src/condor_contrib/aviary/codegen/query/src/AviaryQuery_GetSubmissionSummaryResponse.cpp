

        /**
         * GetSubmissionSummaryResponse.cpp
         *
         * This file was auto-generated from WSDL
         * by the Apache Axis2/C version: SNAPSHOT  Built on : Mar 10, 2008 (08:35:52 GMT+00:00)
         */
        
            #include "AviaryQuery_GetSubmissionSummaryResponse.h"
          

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
        
        using namespace AviaryQuery;
        
               /*
                * Implementation of the GetSubmissionSummaryResponse|http://query.aviary.grid.redhat.com Element
                */
           AviaryQuery::GetSubmissionSummaryResponse::GetSubmissionSummaryResponse()
        {

        
            qname = NULL;
        
                property_Submissions  = NULL;
              
            isValidSubmissions  = false;
        
                  qname =  axutil_qname_create (Environment::getEnv(),
                        "GetSubmissionSummaryResponse",
                        "http://query.aviary.grid.redhat.com",
                        NULL);
                
        }

       AviaryQuery::GetSubmissionSummaryResponse::GetSubmissionSummaryResponse(std::vector<AviaryCommon::SubmissionSummary*>* arg_Submissions)
        {
             
                   qname = NULL;
             
               property_Submissions  = NULL;
             
            isValidSubmissions  = true;
            
                 qname =  axutil_qname_create (Environment::getEnv(),
                       "GetSubmissionSummaryResponse",
                       "http://query.aviary.grid.redhat.com",
                       NULL);
               
                    property_Submissions = arg_Submissions;
            
        }
        AviaryQuery::GetSubmissionSummaryResponse::~GetSubmissionSummaryResponse()
        {
            resetAll();
        }

        bool WSF_CALL AviaryQuery::GetSubmissionSummaryResponse::resetAll()
        {
            //calls reset method for all the properties owned by this method which are pointers.

            
             resetSubmissions();//AviaryCommon::SubmissionSummary
          if(qname != NULL)
          {
            axutil_qname_free( qname, Environment::getEnv());
            qname = NULL;
          }
        
            return true;

        }

        

        bool WSF_CALL
        AviaryQuery::GetSubmissionSummaryResponse::deserialize(axiom_node_t** dp_parent,bool *dp_is_early_node_valid, bool dont_care_minoccurs)
        {
          axiom_node_t *parent = *dp_parent;
          
          bool status = AXIS2_SUCCESS;
           
         const axis2_char_t* text_value = NULL;
         axutil_qname_t *mqname = NULL;
          
               int i = 0;
            
               int sequence_broken = 0;
               axiom_node_t *tmp_node = NULL;
            
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
                        
                          first_node = axiom_node_get_first_child(parent, Environment::getEnv());
                          
                    }
                    else
                    {
                        WSF_LOG_ERROR_MSG(Environment::getEnv()->log, WSF_LOG_SI,
                              "Failed in building adb object for GetSubmissionSummaryResponse : "
                              "Expected %s but returned %s",
                              axutil_qname_to_string(qname, Environment::getEnv()),
                              axutil_qname_to_string(mqname, Environment::getEnv()));
                        
                        return AXIS2_FAILURE;
                    }
                    
                       { 
                    /*
                     * building Submissions array
                     */
                       std::vector<AviaryCommon::SubmissionSummary*>* arr_list =new std::vector<AviaryCommon::SubmissionSummary*>();
                   

                     
                     /*
                      * building submissions element
                      */
                     
                     
                     
                                    element_qname = axutil_qname_create(Environment::getEnv(), "submissions", NULL, NULL);
                                  
                               
                               for (i = 0, sequence_broken = 0, current_node = first_node; !sequence_broken && current_node != NULL;)
                                             
                               {
                                  if(axiom_node_get_node_type(current_node, Environment::getEnv()) != AXIOM_ELEMENT)
                                  {
                                     current_node =axiom_node_get_next_sibling(current_node, Environment::getEnv());
                                     is_early_node_valid = false;
                                     continue;
                                  }
                                  
                                  current_element = (axiom_element_t *)axiom_node_get_data_element(current_node, Environment::getEnv());
                                  mqname = axiom_element_get_qname(current_element, Environment::getEnv(), current_node);

                                  if (axutil_qname_equals(element_qname, Environment::getEnv(), mqname) || !axutil_strcmp("submissions", axiom_element_get_localname(current_element, Environment::getEnv())))
                                  {
                                  
                                      is_early_node_valid = true;
                                      
                                     AviaryCommon::SubmissionSummary* element = new AviaryCommon::SubmissionSummary();
                                          
                                          status =  element->deserialize(&current_node, &is_early_node_valid, false);
                                          
                                          if(AXIS2_FAILURE ==  status)
                                          {
					  WSF_LOG_ERROR_MSG(Environment::getEnv()->log,WSF_LOG_SI, "failed in building element submissions ");
                                          }
                                          else
                                          {
                                            arr_list->push_back(element);
                                            
                                          }
                                        
                                     if(AXIS2_FAILURE ==  status)
                                     {
                                         WSF_LOG_ERROR_MSG(Environment::getEnv()->log, WSF_LOG_SI, "failed in setting the value for submissions ");
                                         if(element_qname)
                                         {
                                            axutil_qname_free(element_qname, Environment::getEnv());
                                         }
                                         if(arr_list)
                                         {
                                            delete arr_list;
                                         }
                                         return false;
                                     }

                                     i++;
                                    current_node = axiom_node_get_next_sibling(current_node, Environment::getEnv());
                                  }
                                  else
                                  {
                                      is_early_node_valid = false;
                                      sequence_broken = 1;
                                  }
                                  
                               }

                               
                                   if (i < 0)
                                   {
                                     /* found element out of order */
                                     WSF_LOG_ERROR_MSG( Environment::getEnv()->log,WSF_LOG_SI,"submissions (@minOccurs = '0') only have %d elements", i);
                                     if(element_qname)
                                     {
                                        axutil_qname_free(element_qname, Environment::getEnv());
                                     }
                                     if(arr_list)
                                     {
                                        delete arr_list;
                                     }
                                     return false;
                                   }
                               

                               if(0 == arr_list->size())
                               {
                                    delete arr_list;
                               }
                               else
                               {
                                    status = setSubmissions(arr_list);
                               }

                              
                            } 
                        
                  if(element_qname)
                  {
                     axutil_qname_free(element_qname, Environment::getEnv());
                     element_qname = NULL;
                  }
                 
          return status;
       }

          bool WSF_CALL
          AviaryQuery::GetSubmissionSummaryResponse::isParticle()
          {
            
                 return false;
              
          }


          void WSF_CALL
          AviaryQuery::GetSubmissionSummaryResponse::declareParentNamespaces(
                    axiom_element_t *parent_element,
                    axutil_hash_t *namespaces, int *next_ns_index)
          {
            
                  /* Here this is an empty function, Nothing to declare */
                 
          }

        
        
        axiom_node_t* WSF_CALL
	AviaryQuery::GetSubmissionSummaryResponse::serialize(axiom_node_t *parent, 
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
            
               int i = 0;
               int count = 0;
               void *element = NULL;
             
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
                                             "http://query.aviary.grid.redhat.com",
                                             "n"); 
                           axutil_hash_set(namespaces, "http://query.aviary.grid.redhat.com", AXIS2_HASH_KEY_STRING, axutil_strdup(Environment::getEnv(), "n"));
                       
                     
                    parent_element = axiom_element_create (Environment::getEnv(), NULL, "GetSubmissionSummaryResponse", ns1 , &parent);
                    
                    
                    axiom_element_set_namespace(parent_element, Environment::getEnv(), ns1, parent);


            
                    data_source = axiom_data_source_create(Environment::getEnv(), parent, &current_node);
                    stream = axiom_data_source_get_stream(data_source, Environment::getEnv());
                  
                       p_prefix = NULL;
                      

                   if (!isValidSubmissions)
                   {
                      
                           /* no need to complain for minoccurs=0 element */
                            
                          
                   }
                   else
                   {
                     start_input_str = (axis2_char_t*)AXIS2_MALLOC(Environment::getEnv()->allocator, sizeof(axis2_char_t) *
                                 (4 + axutil_strlen(p_prefix) + 
                                  axutil_strlen("submissions"))); 
                                 
                                 /* axutil_strlen("<:>") + 1 = 4 */
                     end_input_str = (axis2_char_t*)AXIS2_MALLOC(Environment::getEnv()->allocator, sizeof(axis2_char_t) *
                                 (5 + axutil_strlen(p_prefix) + axutil_strlen("submissions")));
                                  /* axutil_strlen("</:>") + 1 = 5 */
                                  
                     

                   
                   
                     /*
                      * Parsing Submissions array
                      */
                     if (property_Submissions != NULL)
                     {
                        

                            sprintf(start_input_str, "<%s%ssubmissions",
                                 p_prefix?p_prefix:"",
                                 (p_prefix && axutil_strcmp(p_prefix, ""))?":":"");
                            
                         start_input_str_len = axutil_strlen(start_input_str);

                         sprintf(end_input_str, "</%s%ssubmissions>",
                                 p_prefix?p_prefix:"",
                                 (p_prefix && axutil_strcmp(p_prefix, ""))?":":"");
                         end_input_str_len = axutil_strlen(end_input_str);

                         count = property_Submissions->size();
                         for(i = 0; i < count; i++)
                         {
                            AviaryCommon::SubmissionSummary* element = (*property_Submissions)[i];

                            if(NULL == element) 
                            {
                                continue;
                            }

                    
                     
                     /*
                      * parsing submissions element
                      */

                    
                     
                            if(!element->isParticle())
                            {
                                axutil_stream_write(stream, Environment::getEnv(), start_input_str, start_input_str_len);
                            }
                            element->serialize(current_node, parent_element,
                                                                                 element->isParticle() || false, namespaces, next_ns_index);
                            
                            if(!element->isParticle())
                            {
                                axutil_stream_write(stream, Environment::getEnv(), end_input_str, end_input_str_len);
                            }
                            
                         }
                     }
                   
                     
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
             * Getter for submissions by  Property Number 1
             */
            std::vector<AviaryCommon::SubmissionSummary*>* WSF_CALL
            AviaryQuery::GetSubmissionSummaryResponse::getProperty1()
            {
                return getSubmissions();
            }

            /**
             * getter for submissions.
             */
            std::vector<AviaryCommon::SubmissionSummary*>* WSF_CALL
            AviaryQuery::GetSubmissionSummaryResponse::getSubmissions()
             {
                return property_Submissions;
             }

            /**
             * setter for submissions
             */
            bool WSF_CALL
            AviaryQuery::GetSubmissionSummaryResponse::setSubmissions(
                    std::vector<AviaryCommon::SubmissionSummary*>*  arg_Submissions)
             {
                
                 int size = 0;
                 int i = 0;
                 bool non_nil_exists = false;
                

                if(isValidSubmissions &&
                        arg_Submissions == property_Submissions)
                {
                    
                    return true;
                }

                
                 size = arg_Submissions->size();
                 
                 if (size < 0)
                 {
                     WSF_LOG_ERROR_MSG( Environment::getEnv()->log,WSF_LOG_SI,"submissions has less than minOccurs(0)");
                     return false;
                 }
                 for(i = 0; i < size; i ++ )
                 {
                     if(NULL != (*arg_Submissions)[i])
                     {
                         non_nil_exists = true;
                         break;
                     }
                 }

                 

                
                resetSubmissions();

                
                    if(NULL == arg_Submissions)
                         
                {
                    /* We are already done */
                    return true;
                }
                
                        property_Submissions = arg_Submissions;
                        if(non_nil_exists)
                        {
                            isValidSubmissions = true;
                        }
                        
                    
                return true;
             }

            
            /**
             * Get ith element of submissions.
             */
            AviaryCommon::SubmissionSummary* WSF_CALL
            AviaryQuery::GetSubmissionSummaryResponse::getSubmissionsAt(int i)
            {
                AviaryCommon::SubmissionSummary* ret_val;
                if(property_Submissions == NULL)
                {
                    return (AviaryCommon::SubmissionSummary*)0;
                }
                ret_val =   (*property_Submissions)[i];
                
                    return ret_val;
                  
            }

            /**
             * Set the ith element of submissions.
             */
           bool WSF_CALL
            AviaryQuery::GetSubmissionSummaryResponse::setSubmissionsAt(int i,
                    AviaryCommon::SubmissionSummary* arg_Submissions)
            {
                 AviaryCommon::SubmissionSummary* element;
                int size = 0;

                int non_nil_count;
                bool non_nil_exists = false;

                 

                if( isValidSubmissions &&
                    property_Submissions &&
                  
                    arg_Submissions == (*property_Submissions)[i])
                  
                 {
                    
                    return AXIS2_SUCCESS; 
                }

                   
                     non_nil_exists = true;
                  

                if(property_Submissions == NULL)
                {
                    property_Submissions = new std::vector<AviaryCommon::SubmissionSummary*>();
                }
                else{
                /* check whether there already exist an element */
                element = (*property_Submissions)[i];
                }

                
                        if(NULL != element)
                        {
                          
                          
                          
                                delete element;
                             
                        }
                        
                    
                    if(!non_nil_exists)
                    {
                        
                        isValidSubmissions = true;
                        (*property_Submissions)[i]= NULL;
                        
                        return AXIS2_SUCCESS;
                    }
                
                    (*property_Submissions)[i] = arg_Submissions;
                  

               isValidSubmissions = true;
                
                return AXIS2_SUCCESS;
            }

            /**
             * Add to submissions.
             */
            bool WSF_CALL
            AviaryQuery::GetSubmissionSummaryResponse::addSubmissions(
                    AviaryCommon::SubmissionSummary* arg_Submissions)
             {

                
                    if( NULL == arg_Submissions
                     )
                    {
                      
                           return true; 
                        
                    }
                  

                if(property_Submissions == NULL)
                {
                    property_Submissions = new std::vector<AviaryCommon::SubmissionSummary*>();
                }
              
               property_Submissions->push_back(arg_Submissions);
              
                isValidSubmissions = true;
                return true;
             }

            /**
             * Get the size of the submissions array.
             */
            int WSF_CALL
            AviaryQuery::GetSubmissionSummaryResponse::sizeofSubmissions()
            {

                if(property_Submissions == NULL)
                {
                    return 0;
                }
                return property_Submissions->size();
            }

            /**
             * remove the ith element, same as set_nil_at.
             */
            bool WSF_CALL
            AviaryQuery::GetSubmissionSummaryResponse::removeSubmissionsAt(int i)
            {
                return setSubmissionsNilAt(i);
            }

            

           /**
            * resetter for submissions
            */
           bool WSF_CALL
           AviaryQuery::GetSubmissionSummaryResponse::resetSubmissions()
           {
               int i = 0;
               int count = 0;


               
                if (property_Submissions != NULL)
                {
                  std::vector<AviaryCommon::SubmissionSummary*>::iterator it =  property_Submissions->begin();
                  for( ; it <  property_Submissions->end() ; ++it)
                  {
                     AviaryCommon::SubmissionSummary* element = *it;
                
            
                

                if(element != NULL)
                {
                   
                   
                         delete  element;
                     

                   }

                
                
                
               }

             }
                
                    if(NULL != property_Submissions)
                 delete property_Submissions;
                
               isValidSubmissions = false; 
               return true;
           }

           /**
            * Check whether submissions is nill
            */
           bool WSF_CALL
           AviaryQuery::GetSubmissionSummaryResponse::isSubmissionsNil()
           {
               return !isValidSubmissions;
           }

           /**
            * Set submissions to nill (currently the same as reset)
            */
           bool WSF_CALL
           AviaryQuery::GetSubmissionSummaryResponse::setSubmissionsNil()
           {
               return resetSubmissions();
           }

           
           /**
            * Check whether submissions is nill at i
            */
           bool WSF_CALL
           AviaryQuery::GetSubmissionSummaryResponse::isSubmissionsNilAt(int i)
           {
               return (isValidSubmissions == false ||
                       NULL == property_Submissions ||
                     NULL == (*property_Submissions)[i]);
            }

           /**
            * Set submissions to nil at i
            */
           bool WSF_CALL
           AviaryQuery::GetSubmissionSummaryResponse::setSubmissionsNilAt(int i)
           {
                int size = 0;
                int j;
                bool non_nil_exists = false;

                int k = 0;

                if(property_Submissions == NULL ||
                            isValidSubmissions == false)
                {
                    
                    non_nil_exists = false;
                }
                else
                {
                    size = property_Submissions->size();
                    for(j = 0, k = 0; j < size; j ++ )
                    {
                        if(i == j) continue; 
                        if(NULL != (*property_Submissions)[i])
                        {
                            k++;
                            non_nil_exists = true;
                            if( k >= 0)
                            {
                                break;
                            }
                        }
                    }
                }
                

                if( k < 0)
                {
                       WSF_LOG_ERROR_MSG(Environment::getEnv()->log, WSF_LOG_SI, "Size of the array of submissions is beinng set to be smaller than the specificed number of minOccurs(0)");
                       return AXIS2_FAILURE;
                }
 
                if(property_Submissions == NULL)
                {
                    isValidSubmissions = false;
                    
                    return true;
                }
                 
                 /* check whether there already exist an element */
                 AviaryCommon::SubmissionSummary* element = (*property_Submissions)[i];
                if(NULL != element)
                {
                  
                  
                  
                        delete element;
                     
                 }
                 
                    if(!non_nil_exists)
                    {
                        
                        isValidSubmissions = false;
                        (*property_Submissions)[i] = NULL;
                        return AXIS2_SUCCESS;
                    }
                

                
                (*property_Submissions)[i] = NULL;
                
                return AXIS2_SUCCESS;

           }

           

