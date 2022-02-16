package metadata

import (
	"bytes"
	"github.com/go-co-op/gocron"
	"net/http"
	"sync"
	"time"
)

const fidoMDSURL = "https://mds.fidoalliance.org/"

// The SelfUpdatingMetaDataService fetches Metadata from the web given an url and starts a scheduler to self update
type SelfUpdatingMetaDataService struct {
	mdsUrl    string
	mds       *InMemoryMetadataService
	scheduler *gocron.Scheduler
	mu sync.RWMutex
}

// Construct a MDS with the official Fido Alliance MDS Server as Input
func NewSelfUpdatingMetaDataService() (*SelfUpdatingMetaDataService, error) {
	return NewSelfUpdatingMetaDataServiveWithCustomUrl(fidoMDSURL)
}

func NewSelfUpdatingMetaDataServiveWithCustomUrl(authorityUrl string) (*SelfUpdatingMetaDataService, error){
	scheduler := gocron.NewScheduler(time.UTC)

	mds := &SelfUpdatingMetaDataService{
		mdsUrl:    authorityUrl,
		scheduler: scheduler,
		mu:  sync.RWMutex{},
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

func (mds *SelfUpdatingMetaDataService) WebAuthnAuthenticator(aaguid string) *MetadataStatement {
	mds.mu.RLock()
	defer mds.mu.RUnlock()
	return mds.mds.WebAuthnAuthenticator(aaguid)
}

func (mds *SelfUpdatingMetaDataService) U2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement {
	mds.mu.RLock()
	defer mds.mu.RUnlock()
	return mds.mds.U2FAuthenticator(attestationCertificateKeyIdentifier)
}

func (mds *SelfUpdatingMetaDataService) GetNextUpdateDate() string {
	return mds.mds.GetNextUpdateDate()
}

func (mds *SelfUpdatingMetaDataService) GetMetadataNumber() int {
	return mds.mds.GetMetadataNumber()
}