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

MACRO (CONDOR_UNIT_TEST _CNDR_TARGET _SRCS _LINK_LIBS )

	if (BUILD_TESTING)

		enable_testing()

		# we are dependent on boost unit testing framework.
		include_directories(${BOOST_INCLUDE})
		# the structure is a testing subdirectory, so set inlude to go up one level
		include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../)

		set ( LOCAL_${_CNDR_TARGET} ${_CNDR_TARGET} )

		if ( WINDOWS )
			string (REPLACE ".exe" "" ${LOCAL_${_CNDR_TARGET}} ${LOCAL_${_CNDR_TARGET}})
		else()
			if (PROPER)
			  # if you are proper then link the system .so (now .a's by def)
			  add_definitions(-DBOOST_TEST_DYN_LINK)
			endif()
		endif( WINDOWS )

		add_executable( ${LOCAL_${_CNDR_TARGET}} ${_SRCS})
		
		if (BOOST_REF)
		    add_dependencies( ${LOCAL_${_CNDR_TARGET}} ${BOOST_REF} )
		endif()

		if ( WINDOWS )
		  set_property( TARGET ${LOCAL_${_CNDR_TARGET}} PROPERTY FOLDER "tests" )
		  #windows will require runtime to match so make certain we link the right one.
		  target_link_libraries (${LOCAL_${_CNDR_TARGET}} optimized libboost_unit_test_framework-${MSVCVER}-mt-${BOOST_SHORTVER} )
		  target_link_libraries (${LOCAL_${_CNDR_TARGET}} debug libboost_unit_test_framework-${MSVCVER}-mt-gd-${BOOST_SHORTVER} ) 
		else()
		  target_link_libraries (${LOCAL_${_CNDR_TARGET}}  -lboost_unit_test_framework )
		endif ( WINDOWS )

		condor_set_link_libs( ${LOCAL_${_CNDR_TARGET}} "${_LINK_LIBS}" )

		add_test ( ${LOCAL_${_CNDR_TARGET}}_unit_test ${LOCAL_${_CNDR_TARGET}} )

		APPEND_VAR( CONDOR_TESTS ${_CNDR_TARGET} )

	endif(BUILD_TESTING)

ENDMACRO(CONDOR_UNIT_TEST)
