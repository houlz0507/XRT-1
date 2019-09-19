/**
 * Copyright (C) 2018 - 2019 Xilinx, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef __SectionPartitionMetadata_h_
#define __SectionPartitionMetadata_h_

// ----------------------- I N C L U D E S -----------------------------------

// #includes here - please keep these to a bare minimum!
#include "Section.h"
#include "FDTProperty.h"
#include <boost/functional/factory.hpp>
#include <boost/property_tree/json_parser.hpp>

// ------------ F O R W A R D - D E C L A R A T I O N S ----------------------
// Forward declarations - use these instead whenever possible...

// ------------- C L A S S :   S e c t i o n D T C ---------------------------

class SectionPartitionMetadata : public Section {
 public:
  SectionPartitionMetadata();
  virtual ~SectionPartitionMetadata();

 public:
  virtual bool doesSupportAddFormatType(FormatType _eFormatType) const;
  virtual bool doesSupportDumpFormatType(FormatType _eFormatType) const;
  virtual void appendToSectionMetadata(const boost::property_tree::ptree& _ptAppendData, boost::property_tree::ptree& _ptToAppendTo);

 protected:
  virtual void marshalToJSON(char* _pDataSection, unsigned int _sectionSize, boost::property_tree::ptree& _ptree) const;
  virtual void marshalFromJSON(const boost::property_tree::ptree& _ptSection, std::ostringstream& _buf) const;

 protected:
   static const FDTProperty::PropertyNameFormat m_propertyNameFormat;


 private:
  // Purposefully private and undefined ctors...
  SectionPartitionMetadata(const SectionPartitionMetadata& obj);
  SectionPartitionMetadata& operator=(const SectionPartitionMetadata& obj);

 private:
  // Static initializer helper class
  static class _init {
   public:
      _init() { registerSectionCtor(PARTITION_METADATA, "PARTITION_METADATA", "partition_metadata", false, false, boost::factory<SectionPartitionMetadata *>()); }
  } _initializer;
};

#endif
