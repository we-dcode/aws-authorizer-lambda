package authorizer

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateToken(t *testing.T) {

	userPoolURL := "https://cognito-idp.il-central-1.amazonaws.com/il-central-1_5SjnRdPZM"
	auth, err := NewAuthorizerWithAudience(userPoolURL, "6j1v2boo9qam0a9ii50gdnnuos")
	assert.Nil(t, err)
	assert.NotNil(t, auth)

	claims, err := auth.ParseAndVerifyToken("eyJraWQiOiIxa2ZWamJFeHJPd2UySEdyVWFwV2cxMTRtYVwveUhYRWZESHEzclwvWTVCRWM9IiwiYWxnIjoiUlMyNTYifQ.eyJjdXN0b206cGFzc3BvcnRfbnVtIjoiNDYyOFwvMTQyOTMxIiwic3ViIjoiMWFkMzAyYmMtZDBhMS03MDMyLTA2M2ItYjhhYzhkNzk3NDJiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5pbC1jZW50cmFsLTEuYW1hem9uYXdzLmNvbVwvaWwtY2VudHJhbC0xXzVTam5SZFBaTSIsImNvZ25pdG86dXNlcm5hbWUiOiIxYWQzMDJiYy1kMGExLTcwMzItMDYzYi1iOGFjOGQ3OTc0MmIiLCJsb2NhbGUiOiJoZSIsIm9yaWdpbl9qdGkiOiIwOWQyYjQxNi03OTNkLTQwOGEtYmVhOC1mODkxZjEzNWNhZWQiLCJhdWQiOiI2ajF2MmJvbzlxYW0wYTlpaTUwZ2RubnVvcyIsImV2ZW50X2lkIjoiYjNiYWQ0MWMtNGYyZC00NTdjLTkxZjEtNzA1ZWExNTExZDFkIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE3MTM0NzgzODYsImV4cCI6MTcxMzU2NDc4NiwiaWF0IjoxNzEzNDc4Mzg2LCJqdGkiOiIzODYxNjQ2NS0xNjE3LTQzZmQtOWM2Ni1mYzZlMTM3NzgyMGUiLCJlbWFpbCI6ImRvcm9uLm5haHVtQGdtYWlsLmNvbSJ9.gE1NA8Q_cvBOKFT_w92vNTS5xuE0TOjWDqIZuMu2Cfh_KYp8xE7teuo49qHop62AZxtBOm_7kXr7rdbhpH7a_YEFLYrm3p8rrWOc3_kAryfjdwid7--RDXZNjAapGrqTTMukgIWl0EYyL-xO6fnkwiXFPGp_Wdl69gQ9khpmbAgAYBdAV6grCD2wFEmIBvyVhzyjuYEv_cz-n8UOyJ-__y4EksuOz4J6uKVelvNO4sbccFzqLIuAwWX60bh7ygW4LmFIaLWI6vwoi1lqKOqJ7YCcOzGs19Br4aQ5BAI-XWIn-s98GtwAmJSL6KJ_1GqMepk7ywWw2kw8_6wjzCuEWw")
	assert.Nil(t, err)
	assert.NotNil(t, claims)
}