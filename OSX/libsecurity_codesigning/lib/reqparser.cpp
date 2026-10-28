/*
 * Copyright (c) 2006-2007,2011 Apple Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

//
// reqparser - interface to Requirement language parser/compiler
//
#include "reqparser.h"
#include "antlrplugin.h"
#include "cserror.h"
#include <CoreFoundation/CoreFoundation.h>

namespace Security {
namespace CodeSigning {


//
// Drive the statically linked parser and translate syntax errors into a CFError.
// security_codesigning already includes antlrplugin.cpp, its lexer and grammar;
// no separately loaded csparser.bundle is needed.
//
template <class Result, class Source>
const Result *parse(Source source, const Result *(*AntlrPlugin::*func)(Source, string &))
{
	string errors;
	if (const Result *result = (findAntlrPlugin()->*func)(source, errors))
		return result;
	else
		CSError::throwMe(errSecCSReqInvalid, kSecCFErrorRequirementSyntax, CFTempString(errors));		
}


//
// Implement the template instances through the parser's supported entry points.
// Any other combination of input and output types will cause linker errors.
//
template <>
const Requirement *RequirementParser<Requirement>::operator () (std::FILE *source)
{
	return parse(source, &AntlrPlugin::fileRequirement);
}

template <>
const Requirement *RequirementParser<Requirement>::operator () (const std::string &source)
{
	return parse(source, &AntlrPlugin::stringRequirement);
}

template <>
const Requirements *RequirementParser<Requirements>::operator () (std::FILE *source)
{
	return parse(source, &AntlrPlugin::fileRequirements);
}

template <>
const Requirements *RequirementParser<Requirements>::operator () (const std::string &source)
{
	return parse(source, &AntlrPlugin::stringRequirements);
}

template <>
const BlobCore *RequirementParser<BlobCore>::operator () (std::FILE *source)
{
	return parse(source, &AntlrPlugin::fileGeneric);
}

template <>
const BlobCore *RequirementParser<BlobCore>::operator () (const std::string &source)
{
	return parse(source, &AntlrPlugin::stringGeneric);
}


}	// CodeSigning
}	// Security
