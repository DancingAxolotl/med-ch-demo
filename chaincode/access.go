package main

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/peer"
)

const (
	// DoctorPublicKey database key prefix for doctor keys
	DoctorPublicKey = "__access_public_key_"
	// DoctorAccessKey database key prefix for doctor access
	DoctorAccessKey = "__access_doctor_"
)

// MedicalRecordChaincode is the object that contains all of the chaincode that can be executed
type AccessControl struct {
	record *MedicalRecordChaincode
}

type AccessType int

const (
	None AccessType = 0
	Info AccessType= 1
	Full AccessType= 2
)

// registerDoctor adds doctor key to database
func (t *AccessControl) registerDoctor(stub shim.ChaincodeStubInterface, doctor string, doctorKey byte[]) bool, error
{
	key, _ := stub.CreateCompositeKey(DoctorPublicKey, []string{doctor})
	data, err := stub.GetState(stub, key)

	if err != nil {
		return false, err
	}

	if data != nil {
		return false, error("Already registered")
	}

	stub.PutState(key, doctorKey)

	return true, nil
}

// setAccess sets doctor access level, returns true if access was changed
func (t *AccessControl) setAccess(stub shim.ChaincodeStubInterface, patientId uint64, doctor string, accType AccessType) bool, error
{
	accesskey, _ := stub.CreateCompositeKey(DoctorAccessKey, []string{doctor, fmt.Sprint(patientId)})
	current, err := t.record.getValue(stub, accesskey)

	if (err != nil || current == accType) {
		return false, err
	}

	t.record.setValue(stub, accesskey, accType)

	return true, nil
}

// checkAccess returns doctor access level
func (t *AccessControl) checkAccess(stub shim.ChaincodeStubInterface, patientId uint64, doctor string, caller byte[]) AccessType, error
{
	key, _ := stub.CreateCompositeKey(DoctorPublicKey, []string{doctor})
	data, err := stub.GetState(stub, key)

	if err != nil {
		return 0, err
	}

	if data == nil {
		return 0, error("Doctor not registered")
	}

	if data != caller {
		return 0, error("Invalid caller certificate")
	}

	accesskey, _ := stub.CreateCompositeKey(MetadataKey, []string{"doctor", fmt.Sprint(patientId)})
	current, err := t.record.getValue(stub, accesskey)

	if err != nil {
		return 0, err
	}

	return current, nil
}
