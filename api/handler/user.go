package handle

import (
	"errors"
	"fmt"

	mfa "2fatvalidate/api/mfa"
	"2fatvalidate/api/utils"
)

func ValidatePermission(u utils.User) error {
	var requestData utils.User

	requestData.Name = u.Name
	requestData.Auth = u.Auth

	if requestData.Auth == "permission" {
		err := mfa.GetToken(requestData)
		if err != nil {
			return err
		}

		fmt.Printf("Validate Permission With Success, Continue Your Acess")
	} else {

		return errors.New("Dont Have Permission")
	}

	return nil
}
