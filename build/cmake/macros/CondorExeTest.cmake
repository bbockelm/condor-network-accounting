 ###############################################################
 # 
 # Copyright 2011 Red Hat, Inc. 
 # 
 # Licensed under the Apache License, Version 2.0 (the "License"); you 
 # may not use this file except in compliance with the License.  You may 
 # obtain a copy of the License at 
 # 
 #    http://www.apache.org/licenses/LICENSE-2.0 
 # 
 # Unless required by applicable law or agreed to in writing, software 
 # distributed under the License is distributed on an "AS IS" BASIS, 
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and 
 # limitations under the License. 
 # 
 ############################################################### 

MACRO (CONDOR_EXE_TEST _CNDR_TARGET _SRCS _LINK_LIBS )

	if (BUILD_TESTING)

		set ( LOCAL_${_CNDR_TARGET} ${_CNDR_TARGET} )

		if ( WINDOWS )
			string (REPLACE ".exe" "" ${LOCAL_${_CNDR_TARGET}} ${LOCAL_${_CNDR_TARGET}})
		endif( WINDOWS )

		add_executable( ${LOCAL_${_CNDR_TARGET}} EXCLUDE_FROM_ALL ${_SRCS})

		set_target_properties( ${LOCAL_${_CNDR_TARGET}} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${TEST_TARGET_DIR} )
		
		if ( WINDOWS )
			set_property( TARGET ${LOCAL_${_CNDR_TARGET}} PROPERTY FOLDER "tests" )
		endif ( WINDOWS )

		condor_set_link_libs( ${LOCAL_${_CNDR_TARGET}} "${_LINK_LIBS}" )

		if ( DARWIN )
			add_custom_command( TARGET ${LOCAL_${_CNDR_TARGET}}
				POST_BUILD
				WORKING_DIRECTORY ${TEST_TARGET_DIR}
				COMMAND ${CMAKE_SOURCE_DIR}/src/condor_scripts/macosx_rewrite_libs ${LOCAL_${_CNDR_TARGET}} )
		endif()

		APPEND_VAR( CONDOR_TESTS ${_CNDR_TARGET} )

	endif(BUILD_TESTING)

ENDMACRO(CONDOR_EXE_TEST)
