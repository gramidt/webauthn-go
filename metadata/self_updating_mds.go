package metadata

import (
	"bytes"
	"github.com/go-co-op/gocron"
	"net/http"
	"sync"
	"time"
)

const FidoMDSURL = "https://mds.fidoalliance.org/"

// The SelfUpdatingMetaDataService fetches Metadata from the web given an url and starts a scheduler to self update
type SelfUpdatingMetaDataService struct {
	mdsUrl    string
	mds       *InMemoryMetadataService
	scheduler *gocron.Scheduler
	mu        sync.RWMutex
}

// Construct a MDS with the official Fido Alliance MDS Server as Input
func NewSelfUpdatingMetaDataService() (*SelfUpdatingMetaDataService, error) {
	return NewSelfUpdatingMetaDataServiveWithCustomUrl(FidoMDSURL)
}

func NewSelfUpdatingMetaDataServiveWithCustomUrl(authorityUrl string) (*SelfUpdatingMetaDataService, error) {
	scheduler := gocron.NewScheduler(time.UTC)

	mds := &SelfUpdatingMetaDataService{
		mdsUrl:    authorityUrl,
		scheduler: scheduler,
		mu:        sync.RWMutex{},
	}
	err := mds.Update()
	if err != nil {
		return nil, err
	}

	// Start Scheduler
	_, err = scheduler.Every(1).Day().At("00:00").Do(mds.Update)
	if err != nil {
		return nil, err
	}
	scheduler.StartAsync()
	return mds, nil
}

func (mds *SelfUpdatingMetaDataService) fetchMetadata() ([]byte, error) {
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Get(mds.mdsUrl)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (mds *SelfUpdatingMetaDataService) Update() error {
	buf, err := mds.fetchMetadata()
	if err != nil {
		return err
	}
	inner, err := NewInMemoryMetadataService(buf)
	if err != nil {
		return err
	}
	mds.mu.Lock()
	defer mds.mu.Unlock()
	mds.mds = inner
	return nil
}

func (mds *SelfUpdatingMetaDataService) GetWebAuthnAuthenticator(aaguid string) *MetadataStatement {
	mds.mu.RLock()
	defer mds.mu.RUnlock()
	return mds.mds.GetWebAuthnAuthenticator(aaguid)
}

func (mds *SelfUpdatingMetaDataService) GetU2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement {
	mds.mu.RLock()
	defer mds.mu.RUnlock()
	return mds.mds.GetU2FAuthenticator(attestationCertificateKeyIdentifier)
}

// GetNextUpdateDate returns the date of the next scheduled update of the Metadata
func (mds *SelfUpdatingMetaDataService) GetNextUpdateDate() string {
	return mds.mds.GetNextUpdateDate()
}

// GetMetadataNumber returns the current number of the Metadata
func (mds *SelfUpdatingMetaDataService) GetMetadataNumber() int {
	return mds.mds.GetMetadataNumber()
}

// GetEntries returns All Metadata entries
func (mds *SelfUpdatingMetaDataService) GetEntries() []MetadataBLOBPayloadEntry {
	return mds.mds.Metadata.Entries
}
