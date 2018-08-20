package gotrax

import (
	"time"

	. "gopkg.in/check.v1"
)

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForCorrectInstanceTag(c *C) {
	cp := &ClientProfile{
		InstanceTag: 0x12345678,
	}
	c.Assert(cp.Validate(0x88898888), ErrorMatches, "invalid instance tag in client profile")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_validatesACorrectClientProfile(c *C) {
	cp := generateSitaTestData().clientProfile
	c.Assert(cp.Validate(sita.instanceTag), IsNil)
}

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForCorrectSignature(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.InstanceTag = 0xBADBADBA
	c.Assert(cp.Validate(0xBADBADBA), ErrorMatches, "invalid signature in client profile")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForExpiry(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	cp.Sig = &EddsaSignature{s: cp.GenerateSignature(sita.longTerm)}
	c.Assert(cp.Validate(sita.instanceTag), ErrorMatches, "client profile has expired")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_versionsInclude4(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.Versions = []byte{0x03}
	cp.Sig = &EddsaSignature{s: cp.GenerateSignature(sita.longTerm)}
	c.Assert(cp.Validate(sita.instanceTag), ErrorMatches, "client profile doesn't support version 4")
}

func (s *GotraxSuite) Test_ClientProfile_Equals_returnsTrueIfTheyAreEqual(c *C) {
	cp1 := generateSitaTestData().clientProfile
	cp2 := generateSitaTestData().clientProfile
	c.Assert(cp1.Equals(cp2), Equals, true)
	c.Assert(cp2.Equals(cp1), Equals, true)
	cp1.Versions = []byte{0x03}
	c.Assert(cp1.Equals(cp2), Equals, false)
	c.Assert(cp2.Equals(cp1), Equals, false)
}

func (s *GotraxSuite) Test_ClientProfile_HasExpired_returnsWhetherItsExpired(c *C) {
	cp := &ClientProfile{
		Expiration: time.Date(2028, 11, 5, 13, 46, 00, 13, time.UTC),
	}
	c.Assert(cp.HasExpired(), Equals, false)

	cp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	c.Assert(cp.HasExpired(), Equals, true)
}
